# Contributing to znuzhgfw

Thank you for contributing to `znuzhgfw`.

This project welcomes focused improvements to scanning accuracy, reporting quality, tests, packaging, and documentation. Contributions should prioritize clarity, maintainability, and false-positive control over raw finding volume.

## Before You Start

- Open an issue or start a discussion if the proposed change is large or ambiguous.
- Keep pull requests focused. Small, reviewable changes are preferred over broad rewrites.
- Do not add undocumented behavior. If the CLI or reporting output changes, update the relevant documentation.

## Local Setup

```bash
git clone https://github.com/<your-username>/znuzhgfw.git
cd znuzhgfw
python -m venv .venv
```

Activate the environment:

```bash
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Install the project in editable mode:

```bash
pip install -e .
```

## Development Workflow

1. Create a topic branch from `main`.
2. Make the smallest change that solves the problem.
3. Add or update tests when behavior changes.
4. Run the local validation commands.
5. Open a pull request with a clear description of:
   - what changed
   - why it changed
   - how it was tested

Example branch names:

- `docs/refresh-readme`
- `fix/rate-limit-heuristics`
- `test/report-regression`

## Validation

Run tests:

```bash
pytest -q
```

Build the package:

```bash
python -m build
```

Check package metadata:

```bash
python -m twine check dist/*
```

Optional install smoke test:

```bash
python -m pip uninstall znuzhgfw -y
python -m pip install dist/*.whl
znuzhgfw --help
```

On PowerShell, expand the wheel path explicitly if wildcard installation does not resolve:

```powershell
python -m pip install (Get-ChildItem dist\*.whl | Select-Object -ExpandProperty FullName)
```

## Contribution Guidelines

- Prefer clear, direct implementations over clever ones.
- Keep scanner behavior evidence-oriented.
- Do not raise severity based on weak patterns alone.
- Preserve backward compatibility for documented CLI options unless there is a strong reason to change them.
- Add tests for bug fixes and regression-prone behavior.
- Keep documentation accurate and aligned with the current codebase.

## Security-Related Changes

If your change fixes a vulnerability in the project itself, avoid disclosing sensitive details in a public issue before maintainers review it. Follow the private reporting guidance in [SECURITY.md](SECURITY.md).

## Code of Conduct

By participating in this project, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
