---
name: ponytail
version: project-adapter-1
description: Whole-repo simplification and over-engineering review for Phenix AP PageBuilder Guard.
---

# Ponytail project adapter

Review the whole repository looking only for unnecessary complexity.

Rank findings with these tags:

- `delete`: dead code, dead feature, unused state or speculative flexibility;
- `native`: custom code replaceable by PHP/PrestaShop native behavior;
- `yagni`: abstraction or feature with no current requirement;
- `shrink`: same behavior in fewer lines and fewer branches.

Never remove security validation, atomic writes, rollback/data-loss protection, CSRF checks, validator requirements, compatibility required by a real supported archive, or regression tests.

For this module specifically, scanner remediation/quarantine is out of scope: the scanner is read-only and Phenix Malware Scanner owns quarantine.

End every simplification pass with the approximate net line reduction and list any complexity intentionally retained with its reason.
