# Dependency Licenses

This document lists all dependencies used by AgentSec and their licenses.

## Production Dependencies

| Package | License | Notes |
|---------|---------|-------|
| pydantic | MIT | Permissive |
| typer | MIT | Permissive |
| jinja2 | BSD-3-Clause | Permissive |
| pyyaml | MIT | Permissive |
| pydot | MIT | Permissive |
| rich | MIT | Permissive (optional) |
| openai | MIT | Permissive (optional) |
| psutil | BSD-3-Clause | Permissive (optional) |
| fastapi | MIT | Permissive (optional) |
| uvicorn | BSD-3-Clause | Permissive (optional) |

## Development Dependencies

| Package | License | Notes |
|---------|---------|-------|
| pytest | MIT | Permissive |
| pytest-cov | MIT | Permissive |
| black | MIT | Permissive |
| ruff | MIT | Permissive |
| mypy | MIT | Permissive |
| httpx | BSD-3-Clause | Permissive |
| pre-commit | MIT | Permissive |

## License Summary

**All dependencies use permissive licenses** (MIT or BSD-3-Clause):
- ✅ No copyleft or restrictive licenses
- ✅ Safe for commercial use
- ✅ No license contamination concerns
- ✅ Compatible with Apache 2.0

## Verification

Last verified: 2026-09-23

To verify current dependency licenses:
```bash
pip install pip-licenses
pip-licenses --format=markdown --with-urls
```

## Notes

- All listed dependencies are industry-standard, well-maintained packages
- Optional dependencies (rich, openai, psutil, fastapi, uvicorn) are only needed for specific features
- Core functionality requires minimal dependencies (pydantic, typer, jinja2, pyyaml, pydot)