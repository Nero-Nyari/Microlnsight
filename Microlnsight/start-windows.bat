@echo off
python -X utf8 "%~dp0launch_cli.py" %*
exit /b %errorlevel%
