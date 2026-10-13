"""Exercise real full-screen key events with isolated data and mocked transport."""
import asyncio
import importlib.util
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
        self.runner = asyncio.create_task(self.ui.app.run_async())
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
        position = self.ui.messages.buffer.cursor_position
        self.pipe.send_text('\x1b[5~')
        await asyncio.sleep(0.08)
        self.assertLess(self.ui.messages.buffer.cursor_position, position)
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
        self.assertIn('提问或输入', rendered)
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
        self.assertIn('提问或输入', text)
        self.assertIn('Ctrl+Q', text)


if __name__ == '__main__':
    unittest.main()
