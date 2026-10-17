# Contributing to LUME Security Toolkit

Thank you for your interest in contributing to LUME!

## Development Workflow

1. **Fork and Clone**: Clone the repository to your local development machine.
2. **Set up Environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -e ".[dev]"
   ```
3. **Branching Model**:
   - Create a feature branch: `git checkout -b feature/my-new-rule`
   - Target pull requests against `develop`.

## Code Quality Standards
Before opening a pull request, ensure all tests and linter checks pass:
```bash
# Run Ruff linting
ruff check .

# Run Pytest suite
pytest -v
```

## Security & Ethics
- Never commit real API keys, secrets, or confidential model system prompts.
- Test cases must use synthetic canary tokens.
- All testing against external endpoints requires explicit authorization.
