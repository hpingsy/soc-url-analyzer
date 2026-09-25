# Project instructions

## Development
- Use Python 3.13.
- Use pytest for unit tests.
- Use Ruff for linting.
- Keep functions small and testable.

## Security
- Never commit API keys or credentials.
- Never execute or visit submitted URLs.
- Treat all URL input as untrusted.
- Do not log sensitive information.
- Never automatically modify firewall rules.

## Workflow
- Explain significant changes.
- Add tests for new features.
- Run tests before proposing a commit.
- Do not push or merge without approval.

## Code review
- Flag unexpected outbound network requests.
- Flag changes that bypass URL validation.
- Flag removal of security tests.
