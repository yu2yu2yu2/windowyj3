@echo off
chcp 65001 >nul

echo.
echo 🐍 Python依赖安装脚本
echo ================================================
echo 为Windows应急响应数据收集器安装Python依赖
echo ================================================
echo.

REM 检查Python是否安装
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ 未检测到Python环境
    echo.
    echo 请先安装Python:
    echo 1. 访问 https://www.python.org/downloads/
    echo 2. 下载并安装最新版本的Python
    echo 3. 安装时勾选 "Add Python to PATH"
    echo.
    pause
    exit /b 1
)

echo ✅ 检测到Python环境
python --version

echo.
echo 📦 开始安装依赖包...
echo.

REM 升级pip
echo 升级pip...
python -m pip install --upgrade pip

REM 安装psutil (进程和系统信息)
echo 安装psutil (进程和系统信息)...
pip install psutil

REM 安装其他可能需要的包
echo 安装其他依赖包...
pip install requests
pip install colorama

echo.
echo ✅ 依赖安装完成!
echo.
echo 现在可以运行Python版本的数据收集器:
echo python windows_emergency_collector.py
echo.
pause