"""Exercise real full-screen key events with isolated data and mocked transport."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
HAS_TUI = importlib.util.find_spec('prompt_toolkit') is not None
if HAS_TUI:
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput
    from prompt_toolkit.data_structures import Size
    import tui
    import guard_cli


@unittest.skipUnless(HAS_TUI, 'full-screen UI dependency not installed')
class WorkbenchTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / 'backend/data')
        self.addCleanup(self.temp.cleanup)
        self.store, self.profiles = guard_cli.resources(Path(self.temp.name) / 'agent.db')
        self.pipe_context = create_pipe_input()
        self.pipe = self.pipe_context.__enter__()
        self.addCleanup(self.pipe_context.__exit__, None, None, None)
        self.ui = tui.Workbench(self.store, self.profiles, 'windows', self.temp.name,
                                input=self.pipe, output=DummyOutput())
        self.runner = asyncio.create_task(self.ui.app.run_async(set_exception_handler=False))
        await asyncio.sleep(0.08)

    async def asyncTearDown(self):
        if not self.runner.done():
            self.ui.request_exit()
        await asyncio.wait_for(self.runner, 5)

    async def until(self, predicate):
        for _ in range(150):
            if predicate():
                return
            await asyncio.sleep(0.02)
        self.fail('UI did not reach expected state')

    async def command(self, text):
        self.pipe.send_text(text + '\r')
        await asyncio.sleep(0.08)
        await self.until(lambda: not self.ui.running)

    async def test_demo_and_direct_question_use_selected_task(self):
        await self.command('/demo')
        self.assertIn('合成演示数据', self.ui.messages.text)
        self.assertEqual(self.ui.task_id, self.store.recent()[0]['id'])
        self.profiles.put('local', dict(kind='ollama', base_url='http://localhost:11434', model='demo'))
        with patch('guard_cli.ask', return_value='# 结论\n需要核查') as ask:
            await self.command('请解释线索')
        self.assertEqual(ask.call_args.args[2], self.ui.task_id)
        self.assertIn('【结论】', self.ui.messages.text)
        self.assertFalse(self.ui.pending)

    async def test_task_selection_and_cancel_return_to_command_input(self):
        await self.command('/demo')
        selected = self.ui.task_id
        self.pipe.send_text('/tasks\r')
        await self.until(lambda: self.ui.pending)
        self.pipe.send_text('1\r')
        await self.until(lambda: not self.ui.running)
        self.assertEqual(self.ui.task_id, selected)
        self.pipe.send_text('/models\r')
        await self.until(lambda: self.ui.pending)
        self.pipe.send_text('\x03')
        await self.until(lambda: not self.ui.running)
        self.assertFalse(self.ui.secret)
        self.assertFalse(self.profiles.path.exists())

    async def test_reports_entry_and_scan_route_cancel(self):
        self.pipe.send_text('/reports\r')
        await self.until(lambda: self.ui.pending)
        self.assertIn('新建历史分析', self.ui.prompt)
        self.pipe.send_text('0\r')
        await self.until(lambda: not self.ui.running)
        self.pipe.send_text('/scan\r')
        await self.until(lambda: self.ui.pending and '来源' in self.ui.prompt)
        self.pipe.send_text('4\r')
        await self.until(lambda: self.ui.pending and '新建历史分析' in self.ui.prompt)
        self.pipe.send_text('\x03')
        await self.until(lambda: not self.ui.running)
        self.assertFalse(self.ui.pending)
        self.assertIsNone(self.ui.task_id)

    async def test_hidden_key_and_denied_remote_consent_never_send(self):
        await self.command('/demo')
        self.profiles.put('remote', dict(kind='openai', base_url='https://example.com/v1', model='demo'))
        with patch('guard_cli.ask') as ask:
            self.pipe.send_text('解释\r')
            await self.until(lambda: self.ui.pending and self.ui.secret)
            self.pipe.send_text('private-test-key\r')
            await self.until(lambda: self.ui.pending and 'JSON' in self.ui.prompt)
            self.pipe.send_text('n\r')
            await self.until(lambda: self.ui.pending and '确认' in self.ui.prompt)
            self.pipe.send_text('n\r')
            await self.until(lambda: not self.ui.running)
        ask.assert_not_called()
        self.assertNotIn('private-test-key', self.ui.messages.text)
        self.assertNotIn('private-test-key', self.profiles.path.read_text())
        self.assertFalse(self.ui.secret)
        self.assertEqual(self.ui.editor.text, '')

    async def test_error_unknown_command_and_scroll_controls(self):
        await self.command('/unknown')
        self.assertIn('未知命令', self.ui.messages.text)
        await self.command('无任务提问')
        self.assertIn('请先使用', self.ui.messages.text)
        await self.command('/demo')
        await self.fill()
        position = self.ui.messages.window.vertical_scroll
        self.pipe.send_text('\x1b[5~')
        await asyncio.sleep(0.08)
        self.assertLess(self.ui.messages.window.vertical_scroll, position)
        await self.command('/clear')
        self.assertEqual(self.ui.messages.text, '')

    async def test_narrow_layout_and_control_text(self):
        self.ui.app.output.get_size = lambda: Size(rows=24, columns=60)
        self.ui.append('外部内容\x1b[2J\x07\n')
        self.ui.app.invalidate()
        await asyncio.sleep(0.1)
        screen = self.ui.app.renderer.last_rendered_screen
        self.assertIsNotNone(screen)
        rendered = '\n'.join(''.join(cell.char for x, cell in sorted(row.items()) if x < 60)
                             for y, row in sorted(screen.data_buffer.items()) if y < 24)
        self.assertIn('输入 /scan', rendered)
        self.assertNotIn('最近任务', rendered)
        self.assertNotIn('\x1b', self.ui.messages.text)
        self.assertIn('\\x1b', self.ui.messages.text)
        self.assertTrue(self.ui.app.layout.has_focus(self.ui.editor))

    async def test_exit_waits_for_inflight_operation_to_save(self):
        await self.command('/demo')
        self.profiles.put('local', dict(kind='ollama', base_url='http://localhost:11434', model='demo'))
        release = threading.Event()
        entered = threading.Event()
        def answer(*args, **kwargs):
            entered.set()
            release.wait(3)
            return '已完成'
        try:
            with patch('guard_cli.ask', side_effect=answer):
                self.pipe.send_text('解释\r')
                await self.until(entered.is_set)
                self.pipe.send_text('\x11')
                await self.until(lambda: self.ui.exit_after)
                self.assertFalse(self.runner.done())
                release.set()
                await asyncio.wait_for(self.runner, 3)
        finally:
            release.set()

    async def test_compact_home_keeps_input_visible(self):
        self.ui.app.output.get_size = lambda: Size(rows=18, columns=40)
        self.ui.app.invalidate()
        await asyncio.sleep(.1)
        screen = self.ui.app.renderer.last_rendered_screen
        text = '\n'.join(''.join(cell.char for x, cell in sorted(row.items()) if x < 40)
                         for y, row in sorted(screen.data_buffer.items()) if y < 18)
        self.assertIn('/demo', text)
        self.assertIn('输入 /scan', text)
        self.assertIn('Ctrl+Q', text)

    async def test_home_background_is_continuous_across_sizes(self):
        for columns, rows in ((200, 45), (120, 30), (80, 24), (40, 18)):
            with self.subTest(columns=columns, rows=rows):
                self.ui.app.output.get_size = lambda: Size(rows=rows, columns=columns)
                self.ui.app.invalidate()
                await asyncio.sleep(.08)
                screen = self.ui.app.renderer.last_rendered_screen
                rendered = '\n'.join(''.join(screen.data_buffer[y][x].char for x in range(columns))
                                     for y in range(rows))
                self.assertIn('Microlnsight', rendered)
                self.assertNotIn('W I N S E C', rendered)
                self.assertIn('/scan', rendered)
                self.assertIn('/models', rendered)
                self.assertIn('Ctrl+Q', rendered)
                # Check both text cells and padding: the original stripes were
                # caused by differing backgrounds in these two kinds of cell.
                for y in range(1, rows - 7):
                    for x in range(2, self.ui.content_width() + 2):
                        cell = screen.data_buffer[y][x]
                        attrs = self.ui.app._merged_style.get_attrs_for_style_str(cell.style)
                        self.assertEqual(attrs.bgcolor, '161b22', (x, y, cell.char))

    async def test_home_summaries_and_contextual_input(self):
        await self.command('/demo')
        task_id = self.ui.task_id
        self.assertIn('/models', self.ui.input_title())
        await self.command('/home')
        self.assertEqual(self.ui.messages.text, '')
        self.assertEqual(self.ui.task_id, task_id)
        self.assertIn('继续当前任务', ''.join(t for _, t in self.ui.home_text()))
        self.ui.task_id = None
        self.ui.refresh_context()
        self.ui.app.output.get_size = lambda: Size(rows=40, columns=150)
        home = ''.join(t for _, t in self.ui.home_text())
        self.assertIn('合成演示', home)
        self.assertIn('待核查线索', home)
        self.assertNotIn(task_id, home)
        self.assertNotIn(str(self.ui.data_dir), ''.join(t for _, t in self.ui.sidebar_text()))
        await self.command('/workspace')
        self.assertIn(str(self.ui.data_dir), self.ui.messages.text)

    async def test_long_labels_stay_inside_sidebar(self):
        self.ui.model = '配置\x1b[2J / ' + '长模型名称' * 30
        sidebar = self.ui.sidebar_text()
        for _, text in sidebar:
            self.assertLessEqual(tui.get_cwidth(text.rstrip('\n')), 32)
        self.assertNotIn('\x1b', ''.join(t for _, t in sidebar))
        self.assertIn('…', ''.join(t for _, t in sidebar))

    async def test_scope_reasons_keep_sidebar_actions_visible(self):
        await self.command('/demo')
        task = self.store.get(self.ui.task_id)
        task['coverage'].update(input=1000, retained=173, excluded=827,
            excluded_reasons={'unsupported': 827},
            collection={'limit_reached': True, 'warning': True})
        self.store.save(task)
        self.ui.refresh_context()
        self.ui.app.output.get_size = lambda: Size(rows=26, columns=120)
        self.ui.app.invalidate()
        await asyncio.sleep(.1)
        screen = self.ui.app.renderer.last_rendered_screen
        rendered = '\n'.join(''.join(screen.data_buffer[y][x].char for x in range(120)) for y in range(26))
        self.assertIn('达到采集上限', rendered)
        self.assertIn('采集返回警告', rendered)
        self.assertIn('/details', rendered)
        self.assertIn('Ctrl+Q', rendered)
        self.assertIn('达到采集上限', tui.task_result(task))
        self.assertNotIn('范围不完整', tui.task_result(task))


    async def keys(self, text):
        self.pipe.send_text(text)
        await asyncio.sleep(.12)

    async def fill(self):
        self.ui.append(''.join(f'line {i:03d} synthetic output\n' for i in range(250)))
        await asyncio.sleep(.1)

    async def test_mouse_wheel_scrolls_output_without_stealing_input(self):
        await self.fill()
        before = self.ui.messages.window.vertical_scroll
        await self.keys('\x1b[<64;10;10M' * 8)
        self.assertLess(self.ui.messages.window.vertical_scroll, before)
        self.assertTrue(self.ui.app.layout.has_focus(self.ui.editor))

    async def test_scrollbar_drag_changes_output_position(self):
        await self.fill()
        before = self.ui.messages.window.vertical_scroll
        # Actual rendered output window bounds; SGR terminal mouse coordinates are 1-based.
        pos = self.ui.app.renderer.last_rendered_screen.visible_windows_to_write_positions[self.ui.messages.window]
        x, y = pos.xpos + pos.width, pos.ypos + pos.height - 2
        await self.keys(f'\x1b[<0;{x};{y}M\x1b[<32;{x};4M\x1b[<0;{x};4m')
        self.assertLess(self.ui.messages.window.vertical_scroll, before)

    async def test_page_keys_scroll_during_pending_prompt(self):
        await self.keys('/models\r')
        await self.until(lambda: self.ui.pending)
        await self.fill()
        before = self.ui.messages.window.vertical_scroll
        await self.keys('\x1b[5~')
        first_page = self.ui.messages.window.vertical_scroll
        await self.keys('\x1b[5~')
        second_page = self.ui.messages.window.vertical_scroll
        self.assertTrue(self.ui.pending)
        self.assertTrue(self.ui.app.layout.has_focus(self.ui.editor))
        self.assertLess(second_page, before)
        self.assertLess(first_page, before, f'first PageUp: {before} -> {first_page}; second: {second_page}')

    async def test_new_output_preserves_position_when_reading_history(self):
        await self.fill()
        await self.keys('\x1b[5~' * 3)
        before = self.ui.messages.window.vertical_scroll
        self.ui.append('new output while user reads history\n')
        await asyncio.sleep(.1)
        self.assertEqual(self.ui.messages.window.vertical_scroll, before)

    async def test_cancel_scan_preserves_previously_selected_task(self):
        await self.command('/demo')
        selected = self.ui.task_id
        await self.command('/demo')
        self.ui.task_id = selected
        self.ui.refresh_context()
        await self.keys('/scan\r')
        await self.until(lambda: self.ui.pending)
        await self.keys('0\r')
        await self.until(lambda: not self.ui.running)
        self.assertEqual(self.ui.task_id, selected)

    async def test_scan_selects_new_task_while_details_are_open(self):
        await self.keys('/scan\r')
        await self.until(lambda: self.ui.pending)
        await self.keys('3\r')  # synthetic data only
        await self.until(lambda: self.ui.pending and '保护名单' in self.ui.prompt)
        await self.keys('\r')
        await self.until(lambda: self.ui.pending and '导出' in self.ui.prompt)
        self.assertEqual(self.ui.task_id, self.store.recent()[0]['id'])

    async def test_report_export_and_evidence_view_preserve_task(self):
        await self.command('/demo')
        selected = self.ui.task_id
        await self.keys('/details\r')
        await self.until(lambda: self.ui.pending)
        await self.keys('2\r')
        await self.until(lambda: self.ui.pending)
        self.assertIn('全部已保存记录可导出 JSON', self.ui.messages.text)
        await self.keys('3\r')
        await self.until(lambda: self.ui.pending and '路径' in self.ui.prompt)
        target = Path(self.temp.name) / '中文导出.json'
        await self.keys(str(target) + '\r')
        await self.until(target.exists)
        report = json.loads(target.read_text(encoding='utf-8'))
        self.assertEqual(report['task']['id'], selected)
        self.assertEqual(report['analysis_scope'], tui.task_scope(self.store.get(selected)))
        await self.keys('0\r')
        await self.until(lambda: not self.ui.running)
        self.assertEqual(self.ui.task_id, selected)

    async def test_excluded_evidence_menu_shows_saved_raw_and_returns(self):
        await self.command('/demo')
        task = self.store.get(self.ui.task_id)
        task['excluded_records'] = [dict(ref='ssh:8', reason='unsupported', raw='SYNTHETIC_UNKNOWN_MESSAGE')]
        task['coverage']['excluded_evidence'] = dict(total=1, saved=1, omitted=0, truncated=0)
        self.store.save(task)
        await self.keys('/details\r')
        await self.until(lambda: self.ui.pending and '查看排除记录' in self.ui.prompt)
        await self.keys('4\r')
        await self.until(lambda: self.ui.pending and 'SYNTHETIC_UNKNOWN_MESSAGE' in self.ui.messages.text)
        self.assertIn('消息暂不支持', self.ui.messages.text)
        self.assertIn('保存 1 条', self.ui.messages.text)
        await self.keys('0\r')
        await self.until(lambda: not self.ui.running)
        self.assertEqual(self.ui.task_id, task['id'])

    async def test_resize_preserves_pending_input_and_cancel(self):
        await self.keys('/models\r')
        await self.until(lambda: self.ui.pending)
        await self.keys('draft')
        self.ui.app.output.get_size = lambda: Size(rows=18, columns=40)
        self.ui.app.invalidate()
        await asyncio.sleep(.1)
        self.assertEqual(self.ui.editor.text, 'draft')
        await self.keys('\x03')
        await self.until(lambda: not self.ui.running)
        self.assertFalse(self.ui.secret)
        self.assertEqual(self.ui.editor.text, '')

    async def test_cancelled_scan_does_not_create_a_task(self):
        await self.keys('/scan\r')
        await self.until(lambda: self.ui.pending)
        await self.keys('\x03')
        await self.until(lambda: not self.ui.running)
        self.assertEqual(self.store.recent(), [])

    async def test_advertised_home_command_can_leave_detail_menu(self):
        await self.command('/demo')
        await self.keys('/details\r')
        await self.until(lambda: self.ui.pending)
        await self.keys('/home\r')
        self.assertFalse(self.ui.pending, 'The advertised /home command is treated as an invalid numeric menu choice')

    async def test_scrolling_a_wrapped_paragraph_does_not_jump_to_its_start(self):
        self.ui.append('长段落内容' * 1800)
        await asyncio.sleep(.1)
        before = self.ui.messages.window.vertical_scroll_2
        page_rows = self.ui.messages.window.render_info.window_height - 1
        await self.keys('\x1b[5~')
        after = self.ui.messages.window.vertical_scroll_2
        self.assertGreater(before, 30)
        self.assertLess(after, before)
        self.assertEqual(before - after, page_rows)

    async def test_waiting_input_has_no_processing_timer(self):
        await self.keys('/models\r')
        await self.until(lambda: self.ui.pending)
        self.ui.started -= 900
        self.assertIn('等待输入', self.ui.status())
        self.assertNotIn('秒', self.ui.status())
        await self.keys('\x03')
        await self.until(lambda: not self.ui.running)

    async def test_collection_status_uses_saved_stage_not_permission_guess(self):
        await self.command('/demo')
        self.assertIn('未检查本机日志权限', self.ui.collection_status())
        task = self.store.get(self.ui.task_id)
        task.update(source='windows-local', demo=False)
        self.store.save(task)
        self.ui.refresh_context()
        self.assertIn('已完成本机日志读取', self.ui.collection_status())
        # A later model failure must not turn successful collection into a permission failure.
        task.update(status='failed', error='model failed')
        self.store.save(task)
        self.ui.refresh_context()
        self.assertIn('已完成本机日志读取', self.ui.collection_status())
        task['stages'] = []
        self.store.save(task)
        self.ui.refresh_context()
        self.assertIn('采集未完成', self.ui.collection_status())
        self.assertNotIn('权限不足', self.ui.collection_status())

    async def test_failed_scan_selects_its_failed_task(self):
        with patch('guard_cli.collect_windows', side_effect=OSError('test collector failure')), \
                patch('platform.system', return_value='Windows'):
            await self.keys('/scan\r')
            await self.until(lambda: self.ui.pending)
            await self.keys('1\r')
            await self.until(lambda: self.ui.pending and '保护名单' in self.ui.prompt)
            await self.keys('\r')
            await self.until(lambda: not self.ui.running)
        task = self.store.recent()[0]
        self.assertEqual(task['status'], 'failed')
        self.assertEqual(self.ui.task_id, task['id'])
        self.assertIn('采集未完成', self.ui.collection_status())

    async def test_navigation_from_nested_export_does_not_write(self):
        await self.command('/demo')
        selected = self.ui.task_id
        await self.keys('/details\r')
        await self.until(lambda: self.ui.pending)
        await self.keys('3\r')
        await self.until(lambda: self.ui.pending and '路径' in self.ui.prompt)
        await self.keys('/home\r')
        await self.until(lambda: not self.ui.running)
        self.assertFalse(self.ui.pending)
        self.assertEqual(self.ui.messages.text, '')
        self.assertEqual(self.ui.task_id, selected)

    async def test_command_like_secret_stays_hidden_and_is_not_navigation(self):
        await self.command('/demo')
        self.profiles.put('remote', dict(kind='openai', base_url='https://example.com/v1', model='demo'))
        with patch('guard_cli.ask') as ask:
            await self.keys('解释\r')
            await self.until(lambda: self.ui.pending and self.ui.secret)
            await self.keys('/home\r')
            await self.until(lambda: self.ui.pending and not self.ui.secret)
            self.assertNotIn('/home', self.ui.messages.text)
            self.assertIsNone(self.ui.next_command)
            await self.keys('\x03')
            await self.until(lambda: not self.ui.running)
        ask.assert_not_called()

    async def test_scrolling_back_to_bottom_resumes_following_new_output(self):
        await self.fill()
        await self.keys('\x1b[5~' * 3)
        self.assertFalse(self.ui.messages.window.follow_tail)
        await self.keys('\x1b[6~' * 20)
        self.assertTrue(self.ui.messages.window.follow_tail)
        self.ui.append(''.join(f'new {i}\n' for i in range(60)))
        await asyncio.sleep(.1)
        self.assertEqual(self.ui.messages.window.top_row, self.ui.messages.window.max_top)

    async def test_wrapped_history_anchor_survives_resize_and_new_output(self):
        self.ui.append('长段落内容' * 1800)
        await asyncio.sleep(.1)
        await self.keys('\x1b[5~')
        before = self.ui.messages.window.vertical_scroll_2
        self.ui.append('更多内容' * 100)
        await asyncio.sleep(.1)
        self.assertEqual(self.ui.messages.window.vertical_scroll_2, before)
        self.ui.app.output.get_size = lambda: Size(rows=18, columns=40)
        self.ui.app.invalidate()
        await asyncio.sleep(.1)
        self.assertFalse(self.ui.messages.window.follow_tail)
        await self.keys('\x1b[5~')
        self.assertLess(self.ui.messages.window.vertical_scroll_2, before)


if __name__ == '__main__':
    unittest.main()
