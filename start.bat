@echo off
title Daily Toolbox - Django

rem Python 解释器和项目目录（按需修改）
set "PYTHON=d:\ProgramData\miniconda3_2\envs\py12\python.exe"
set "PROJECT_DIR=%~dp0daily_toolbox"

if not exist "%PYTHON%" (
    echo [错误] 未找到 Python: %PYTHON%
    echo 请用记事本编辑本脚本，修改 PYTHON 路径。
    pause
    exit /b 1
)

if not exist "%PROJECT_DIR%\manage.py" (
    echo [错误] 未找到 manage.py: %PROJECT_DIR%
    pause
    exit /b 1
)

cd /d "%PROJECT_DIR%"

echo ==============================================
echo   Daily Toolbox 正在启动...
echo   访问地址: http://127.0.0.1:8000/
echo   停止服务: 按 Ctrl+C 或直接关闭本窗口
echo ==============================================
echo   提示: 如需使用"访问 github"的 hosts 写入
echo   功能，请右键本脚本选择"以管理员身份运行"。
echo ==============================================
echo.

rem 延迟约 2 秒后自动打开浏览器
start "" /min cmd /c "ping -n 3 127.0.0.1 >nul && start http://127.0.0.1:8000/"

"%PYTHON%" manage.py runserver 127.0.0.1:8000 --noreload

echo.
echo 服务器已停止。
pause
