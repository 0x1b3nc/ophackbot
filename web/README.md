# hackbot web UI

Browser chat surface (claude-hq dark theme, MIT) served by `python -m hackbot ui`.

Static files here are preferred when present; the installed package also ships
copies under `hackbot/web_static/`.

```bash
source .venv/bin/activate
export HACKBOT_PROVIDER=codex   # optional
python -m hackbot ui
# → http://127.0.0.1:8765/
```

See `THIRD_PARTY.md` for attribution.
