# Hackbot CLI

```text
python -m hackbot <command> ...
```

## Commands

| Command | Purpose |
|---------|---------|
| `target-init <name>` | Create `targets/<name>` from templates |
| `scope-check <dir> --host HOST [--action TEXT]` | Host/action vs `SCOPE.md` |
| `context <dir>` | Print operating rules + target files |
| `knowledge [task] [--routes]` | Open mandatory study notes for a bug class |
| `plan <dir> --hypothesis ... --target ... --action ... --command ...` | Falsifiable hunt step |
| `evidence <dir> --text/--file [--keep-raw] [--list]` | Save redacted evidence |
| `redact <path>` | Redact a file to stdout |
| `report <dir> --platform bugcrowd\|hackerone\|intigriti ...` | Draft report |
| `run <dir> --tool TOOL --host HOST [--approve]` | Print tool command; execute only with `--approve` |

## Run tools

Supported `--tool` values: `httpx`, `katana`, `nuclei`, `ffuf`, `reconftw`, `hexstrike`, `burp`.

Every active run checks `SCOPE.md` first. Out-of-scope or unconfirmed hosts are blocked.
Without `--approve`, the CLI only prints the command (dry-run).

## Operational output contract

Plans and active steps should include:

1. Falsifiable hypothesis
2. Target/endpoint
3. Preconditions
4. Aggression level 0-3
5. Policy quote
6. Concrete command
7. Expected evidence
8. Stop criteria
9. Cleanup
