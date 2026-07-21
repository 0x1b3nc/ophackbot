@echo off
REM Launch the hackbot interactive agent using the local venv.
REM Just run:  hackbot        (opens the chat, stays open)
REM Or:        hackbot "one shot prompt"
setlocal
set "HERE=%~dp0"
if exist "%HERE%.venv\Scripts\python.exe" (
    "%HERE%.venv\Scripts\python.exe" -m hackbot %*
) else (
    python -m hackbot %*
)
endlocal
