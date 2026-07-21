# Launch the hackbot interactive agent using the local venv.
# Just run:  .\hackbot.ps1        (opens the chat, stays open)
# Or:        .\hackbot.ps1 "one shot prompt"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvPython = Join-Path $here ".venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    & $venvPython -m hackbot @args
} else {
    python -m hackbot @args
}
