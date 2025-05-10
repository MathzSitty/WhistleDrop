@echo off
set HTTP_PROXY=socks5h://127.0.0.1:9150
set HTTPS_PROXY=socks5h://127.0.0.1:9150

REM Adjust path to your virtual environment's python
D:\WhistleDrop\.venv\Scripts D:\WhistleDrop\utils\tor_manager.py %*

REM Variables are local to this .bat execution