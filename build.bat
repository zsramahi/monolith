@echo off
setlocal enabledelayedexpansion

set src=src
set bin=bin
set obj=bin\intermediates
set out=%bin%\monolith.exe
set cflags=-std=c11 -Wall -Wextra -O2
set ldflags=-lbcrypt

if not exist "%bin%" mkdir "%bin%"
if not exist "%obj%" mkdir "%obj%"

set objs=
for /r "%src%" %%f in (*.c) do (
    set "rel=%%f"
    set "rel=!rel:%cd%\%src%\=!"
    set "flat=!rel:\=_!"
    set "flat=!flat:.c=.o!"
    set "target=%obj%\!flat!"
    echo compiling !rel!
    gcc %cflags% -c "%%f" -o "!target!"
    if errorlevel 1 exit /b 1
    set "objs=!objs! !target!"
)

echo linking %out%
gcc!objs! %ldflags% -o "%out%"
if errorlevel 1 exit /b 1

echo build ok
endlocal
