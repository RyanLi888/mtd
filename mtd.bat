@echo off
setlocal

set APP_NAME=mtd-admin.jar
set JVM_OPTS=-Dname=%APP_NAME% -Duser.timezone=Asia/Shanghai -Xms512m -Xmx1024m -XX:MetaspaceSize=128m -XX:MaxMetaspaceSize=512m -XX:+HeapDumpOnOutOfMemoryError

if "%~1"=="" goto usage
if /I "%~1"=="start" goto start
if /I "%~1"=="stop" goto stop
if /I "%~1"=="restart" goto restart
if /I "%~1"=="status" goto status
goto usage

:start
for /f "tokens=1" %%p in ('jps -l ^| findstr /I "%APP_NAME%"') do set PID=%%p
if defined PID (
  echo %APP_NAME% is already running, PID=%PID%
  exit /b 0
)
start "MTD" javaw %JVM_OPTS% -jar %APP_NAME%
echo %APP_NAME% started.
exit /b 0

:stop
for /f "tokens=1" %%p in ('jps -l ^| findstr /I "%APP_NAME%"') do set PID=%%p
if not defined PID (
  echo %APP_NAME% is not running.
  exit /b 0
)
taskkill /F /PID %PID%
exit /b %ERRORLEVEL%

:restart
call "%~f0" stop
call "%~f0" start
exit /b %ERRORLEVEL%

:status
for /f "tokens=1" %%p in ('jps -l ^| findstr /I "%APP_NAME%"') do set PID=%%p
if defined PID (echo %APP_NAME% is running, PID=%PID%) else (echo %APP_NAME% is not running.)
exit /b 0

:usage
echo Usage: %~nx0 ^<start^|stop^|restart^|status^>
exit /b 1
