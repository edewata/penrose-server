@echo off

if "%OS%"=="Windows_NT" @setlocal

rem %~dp0 is expanded pathname of the current script under NT
set DEFAULT_PENROSE_SERVER_HOME=%~dp0..\..\..

if "%PENROSE_SERVER_HOME%"=="" set PENROSE_SERVER_HOME=%DEFAULT_PENROSE_SERVER_HOME%
set DEFAULT_PENROSE_SERVER_HOME=

rem Slurp the command line arguments. This loop allows for an unlimited number
rem of arguments (up to the command line limit, anyway).
set PENROSE_CMD_LINE_ARGS=%1
if ""%1""=="""" goto doneStart
shift
:setupArgs
if ""%1""=="""" goto doneStart
set PENROSE_CMD_LINE_ARGS=%PENROSE_CMD_LINE_ARGS% %1
shift
goto setupArgs
rem This label provides a place for the argument list loop to break out
rem and for NT handling to skip to.

:doneStart
rem find PENROSE_SERVER_HOME if it does not exist due to either an invalid value passed
rem by the user or the %0 problem on Windows 9x
if exist "%PENROSE_SERVER_HOME%\README.txt" goto checkJava

rem check for Penrose in Program Files on system drive
if not exist "%SystemDrive%\Program Files\Penrose" goto checkSystemDrive
set PENROSE_SERVER_HOME=%SystemDrive%\Program Files\Penrose
goto checkJava

:checkSystemDrive
rem check for Penrose in root directory of system drive
if not exist %SystemDrive%\Penrose\README.txt goto checkCDrive
set PENROSE_SERVER_HOME=%SystemDrive%\Penrose
goto checkJava

:checkCDrive
rem check for Penrose in C:\Penrose for Win9X users
if not exist C:\Penrose\README.txt goto noPenroseHome
set PENROSE_SERVER_HOME=C:\Penrose
goto checkJava

:noPenroseHome
echo PENROSE_SERVER_HOME is set incorrectly or Penrose could not be located. Please set PENROSE_SERVER_HOME.
goto end

:checkJava
set _JAVACMD=%JAVACMD%

if "%JAVA_HOME%" == "" goto noJavaHome
if not exist "%JAVA_HOME%\bin\java.exe" goto noJavaHome
if "%_JAVACMD%" == "" set _JAVACMD=%JAVA_HOME%\bin\java.exe
goto runPenrose

:noJavaHome
if "%_JAVACMD%" == "" set _JAVACMD=java.exe
echo.
echo Warning: JAVA_HOME environment variable is not set.
echo.

:runPenrose

set LOCALLIBPATH=%JAVA_HOME%\lib\ext;%JAVA_HOME%\jre\lib\ext
set LOCALLIBPATH=%LOCALLIBPATH%;%PENROSE_SERVER_HOME%\lib
set LOCALLIBPATH=%LOCALLIBPATH%;%PENROSE_SERVER_HOME%\lib\ext

"%_JAVACMD%" %VD_SERVER_OPTS% -Djava.ext.dirs="%LOCALLIBPATH%" -Djava.library.path="%LOCALLIBPATH%" -Dorg.safehaus.penrose.client.home="%PENROSE_SERVER_HOME%" org.safehaus.penrose.federation.FederationClient %PENROSE_CMD_LINE_ARGS%
goto end

:end
set LOCALCLASSPATH=
set LOCALLIBPATH=
set _JAVACMD=
set PENROSE_CMD_LINE_ARGS=

if "%OS%"=="Windows_NT" @endlocal

:mainEnd

