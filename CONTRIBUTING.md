# Contributing to SecureX

Thank you for your interest in contributing to SecureX!

## Development Setup

1. Clone the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Install development dependencies: `pip install -r requirements.txt`
4. Make your changes
5. Write tests for new functionality
6. Run tests: `pytest tests/`
7. Commit with clear messages: `git commit -m "feat: add new feature"`
8. Push and create a Pull Request

## Code Style

- Follow PEP 8 guidelines
- Use type hints where possible
- Write docstrings for functions and classes
- Keep functions focused and small
- Maximum line length: 100 characters

## Testing Requirements

- All new features must have unit tests
- Aim for >80% code coverage
- Integration tests for complex features
- Run `pytest tests/ -v --cov=src` before submitting PR

## Commit Messages

Format: `<type>: <subject>`

Types:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `test:` Adding tests
- `chore:` Maintenance tasks

Example: `feat: add email notification support`

## Pull Request Process

1. Update documentation if needed
2. Update CHANGELOG.md
3. Ensure all tests pass
4. Request review from maintainers
5. Address review feedback

## Reporting Issues

- Use GitHub Issues
- Include system information (OS, Python version)
- Provide error messages and logs
- Include steps to reproduce
