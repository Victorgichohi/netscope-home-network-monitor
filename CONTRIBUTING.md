# Contributing

Thanks for helping improve NetScope.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
pytest
```

Use a test network or isolated lab. Never include real credentials, private keys, `.env` files, packet payloads, personal destination history, or production databases in an issue or pull request.

## Pull requests

- Keep changes focused and consistent with the existing FastAPI and vanilla JavaScript architecture.
- Preserve the metadata-only capture model; do not retain packet payloads.
- Add focused tests for backend behavior.
- Document new environment variables in `.env.example` and `README.md`.
- Explain platform-specific privileges and visibility limitations honestly.
- Run the complete test suite before submitting.

Router integrations should use the existing adapter interface, avoid hard-coded credentials, reject unknown SSH host keys, and default to disabled.
