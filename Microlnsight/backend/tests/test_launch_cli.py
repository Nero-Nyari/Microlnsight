"""The Linux launcher must hand terminal signals directly to the CLI."""
from contextlib import nullcontext
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import launch_cli


class LauncherTests(unittest.TestCase):
    def test_linux_replaces_wrapper_instead_of_waiting_on_a_child(self):
        with patch('launch_cli.runtime_lock', return_value=nullcontext()), \
                patch('launch_cli.recover', return_value=False), \
                patch('launch_cli.runtime_python', return_value=Path(sys.executable)), \
                patch('launch_cli.sys.platform', 'linux'), \
                patch('launch_cli.sys.argv', ['launch_cli.py', 'watch']), \
                patch('launch_cli.os.execv', side_effect=SystemExit(0)) as execute, \
                patch('launch_cli.subprocess.call') as child:
            with self.assertRaises(SystemExit):
                launch_cli.main()
            execute.assert_called_once_with(str(Path(sys.executable)),
                [str(Path(sys.executable)), '-X', 'utf8', str(ROOT / 'agent.py'), 'watch'])
            child.assert_not_called()

    def test_windows_preserves_child_exit_code(self):
        with patch('launch_cli.runtime_lock', return_value=nullcontext()), \
                patch('launch_cli.recover', return_value=False), \
                patch('launch_cli.runtime_python', return_value=Path(sys.executable)), \
                patch('launch_cli.sys.platform', 'win32'), \
                patch('launch_cli.os.execv') as execute, \
                patch('launch_cli.subprocess.call', return_value=7):
            self.assertEqual(launch_cli.main(), 7)
            execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
