# AGENTS.md — Phenix AP PageBuilder Guard

## Project goal

Phenix AP PageBuilder Guard is a small defensive compatibility patch for legacy AP Page Builder 2.x on PrestaShop. Keep it focused: patch documented vulnerable paths, provide runtime validation, file logs, safe backup/rollback, and a read-only targeted scanner.

Current baseline: **1.1.16**.

## Non-negotiable scope

- PrestaShop target: **1.7.x to 8.x**.
- PHP runtime minimum: **7.1**. Public constant visibility required by the Validator is PHP 7.1+; do not claim PHP 5.x compatibility.
- AP Page Builder target: **2.2.0 to 2.4.9**.
- Real archives currently regression-tested: **2.4.1, 2.4.3, 2.4.5, 2.4.8**.
- Never claim a real 2.4.9 archive test unless that archive was actually supplied and tested.
- The scanner MUST stay strictly inside `/modules/appagebuilder/`.
- Never scan the PrestaShop root, themes, uploads, caches, or other modules from this module.
- Scanner is **read-only**. No quarantine, delete, rename, auto-clean, or remediation action belongs here.
- Quarantine/remediation belongs to **Phenix Malware Scanner**, not AP PageBuilder Guard.
- Disable/uninstall MUST NOT silently restore AP Page Builder files.
- Do not falsify AP Page Builder's version number.

## Simplicity rule

Before adding code:

1. Does this feature belong in this module?
2. Can existing code or a PrestaShop/PHP native feature do it?
3. Is it required by a documented vulnerability, validator rule, or reproduced bug?
4. If not, do not add it.

Prefer deletion over abstraction. Do not introduce services, repositories, factories, Composer packages, DB tables, cron jobs, queues, or remote services without a demonstrated requirement.

## Security invariants

### Runtime guard

`PhApPageBuilderGuardCore` is called by patched AP Page Builder code at sensitive points. It is not a permanent background scanner.

- `guardApAjax()` checks are cumulative. Never add an early return that lets `leoajax=1` bypass gallery or `config` validation.
- Keep strict numeric/list validation for known legacy SQLi parameters.
- Unknown AJAX parameters with high-confidence SQLi structure must still be rejected. Inspect the complete value: never truncate before the SQLi detector. Normalize SQL block/conditional comments so `/**/` cannot hide SQL keywords.
- `show_number` must be validated and the sanitized value written back to the request.
- Base64 `config` must tolerate documented obfuscation but reject traversal/wrappers and `product_item_path` injection.
- `form_id` is optional; invalid values may be ignored/logged but absence is not itself malicious.
- `guardGeneratedTemplate()` accepts basename-only `.tpl` targets.
- `guardWriteFile()` must never allow executable/config override files such as PHP/PHTML, `.htaccess`, `.user.ini`, `php.ini`, or `web.config`.
- Allowed generic AP write extensions remain narrowly allow-listed (`tpl`, `js`, `css`, `xml`) unless a real archive proves another legitimate requirement.
- Do not trust raw `$_COOKIE` for the product template path. Use the PrestaShop Context cookie and canonical path validation.
- Path-boundary checks must compare normalized roots with a trailing `/`; sibling paths such as `/shopEVIL/` are outside `/shop/`.
- Generic write targets that are existing symlinks must be rejected.
- The targeted scanner must skip symlink files/directories and verify the canonical `realpath()` of every scanned file still lies below `/modules/appagebuilder/`.

### Logging

- File-only logging, no SQL table.
- Logs live under `/var/phappagebuilderguard/logs/`.
- Current log file is PHP-guarded and chmod 0600.
- Keep rotation bounded.
- `REMOTE_ADDR` is trusted only as the direct peer address; forwarded headers remain untrusted metadata.
- Log only security-relevant AP Page Builder parameters.
- Redact known passwords, tokens, sessions, cookies, secrets, API keys and similar values.
- Never expand logging to entire arbitrary request bodies without a specific incident-analysis requirement.

### Backup/rollback

- Patch writes and restores must remain atomic: temp file in same directory, complete write, permission preservation, rename.
- Pre-patch rollback and manual backup are distinct concepts.
- Manual restore must validate target allow-list and SHA-256.
- Keep backward compatibility with existing legacy backup locations while users may still upgrade from older 1.1.x releases.

## Validator rules — mandatory before every release

These rules were learned from the PrestaShop validator and must not regress:

- Root `.htaccess` present.
- `$this->version` and `config.xml` version identical.
- `$this->description` and `config.xml` description identical.
- Module metadata/description in English.
- Every distributed source file that requires a license header must contain author, copyright and AFL-3.0 license metadata.
- **License-header precedence for the main module file:** `/phappagebuilderguard.php` must start exactly with `<?php\n/**` so the file comment/license header has **no blank line before it**. This is required by the Validator **Licenses** check and matches the previously accepted 1.1.10 packaging. Do not reinsert a blank line there merely to satisfy `blank_line_after_opening_tag`; if the Validator reports both rules, the package-blocking license header requirement takes precedence for this file.
- Smarty templates are mandatory for HTML rendering. Do not build BO HTML in PHP.
- No raw unescaped dynamic Smarty interpolation. Escape user/runtime values.
- PHP coding style must stay compatible with every Validator rule already encountered: short arrays, visibility on constants, prefix increment where appropriate, simple single quotes, `exit` instead of `die`, and correct docblock/blank-line placement.
- Explicitly enforce the rules now seen in production Validator reports: `class_attributes_separation`, `no_extra_blank_lines`, `blank_line_before_statement`, `single_blank_line_at_eof`. `blank_line_after_opening_tag` applies except where it conflicts with the mandatory main-file license-header placement above.
- Package root must be exactly `phappagebuilderguard/`.
- Do not package runtime logs, generated backups, caches, quarantine data, test artifacts, dev skills, or local fixtures.

## Required regression tests before a release

A release is not ready until all applicable gates pass.

### Official PrestaShop Validator gate

Use `lozitax/ps-validator` as the CLI wrapper for the official PrestaShop Validator API. It is a **development/release tool only** and must never be packaged in the module ZIP.

- Upstream: `https://github.com/lozitax/ps-validator.git`.
- The CLI requires **PHP 8.1+**. This does not change the module runtime target of PHP 7.1+.
- Authentication is only through `PRESTASHOP_VALIDATOR_API_KEY`. Never write, commit, echo, archive, or embed this key. In CI it must be a secret.
- Install/update locally with `tools/install_ps_validator.sh`, or provide `PS_VALIDATOR_BIN=/path/to/validator.php`, or expose a `ps-validator` command in `PATH`.
- Preferred full release command: `tests/run_release_gate.sh <release.zip> <ap-archive-dir> [report-base]`. It must run the local gates first and `ps-validator` last.
- `tests/run_ps_validator.sh <release.zip>` may be used separately when only the official Validator gate needs to be rerun.
- Request `--format=all` so JSON, HTML and TXT reports are available for machine checks and human review.
- Exit code `0` is required. Exit code `1` means Validator errors; `2` means usage/configuration; `3` network/API; `4` output write failure. Any non-zero result blocks the release.
- If `PRESTASHOP_VALIDATOR_API_KEY` is missing, the release gate must **fail**, not silently skip the official Validator.
- Always validate the exact final ZIP intended for distribution, after `unzip -t` and all local checks. Do not validate an intermediate directory and then rebuild a different ZIP.

### Syntax/static

- `php -l` every PHP file in the module.
- `node --check` any changed JavaScript.
- Parse `config.xml`.
- Run `tests/static_checks.py`.
- Package contents must not contain `tests/`, `.agents/`, `AGENTS.md`, `README-DEV.md`, `.tools/`, reports, runtime logs, quarantine, or fixtures.

### Patch matrix on real AP archives

For every supplied regression archive (currently 2.4.1, 2.4.3, 2.4.5, 2.4.8):

1. extract a fresh copy;
2. detect the AP version;
3. apply the Guard patch;
4. lint every modified PHP target;
5. apply a second time and prove idempotence;
6. rollback;
7. compare exact SHA-256 with original files;
8. create a manual backup;
9. modify a covered file in the isolated fixture;
10. restore the manual backup and compare exact SHA-256 again.

Fail the release if any target insertion count is not exactly one or if rollback/restore differs from the original bytes.

### Runtime security regressions

At minimum test:

- all known numeric/list SQLi parameters with malicious mutations;
- unknown AJAX parameter SQLi fallback;
- long benign prefixes before a malicious SQL fragment, including >4 KiB and near the runtime request-inspection cap;
- SQL comments and MySQL conditional-comment obfuscation;
- `leoajax + show_number` bypass combination;
- `leoajax + config` traversal combination;
- Base64 whitespace/noise variants;
- optional/missing `form_id`;
- JSON recursion/depth limits;
- legitimate commercial strings (`Pack (`, `Touch (`, `Copy (`, etc.) to prevent regex regressions;
- legitimate English phrases containing SQL-like words (`Select from our new collection`, `Insert into your basket`, `Delete from wishlist`, `Update from supplier`, `Sleep (Deluxe Edition)`, plain `1 and 1=1`) so the generic SQLi fallback does not regress into broad keyword blocking;
- `widget=ApImageGallery` case variants as defense in depth;
- `show_number` array/object input to ensure it is rejected without PHP conversion warnings;
- allowed/forbidden file extensions;
- root sibling paths such as `<root>EVIL`;
- existing symlink write targets;
- scanner symlink files and directories that resolve outside the module;
- raw HTTP cookie ignored vs signed Context cookie accepted only after canonical path validation;
- log redaction and filtering.

Use a fixed random seed for fuzz tests so failures are reproducible. Current project seed: `20260903`.

## Performance rules

- Do not add caches without measurement.
- Request-inspection logic must remain bounded and avoid catastrophic PCRE patterns.
- SQLi fallback must inspect the complete unknown parameter value, but fuzz tests must include large benign values (currently ~1 MiB) to catch accidental pathological behavior.
- Scanner is manual, but still avoid repeated reads and unbounded recursion outside its single root.

## UX rules

- Maintain the current compact light PrestaShop admin design.
- Scope styles under `.phapb-admin`.
- No decorative pseudo-elements that can create rendering artifacts.
- Status must never report `Patch actif` unless every required marker is present, including `_PRODUCTLIST_STORAGE_`.
- Runtime protection explanation must remain explicit: what it does, when it runs, and why disabling it weakens dynamic checks without removing the file patch.

## Release process

1. Run Ponytail repo-wide simplification review. Do not blindly apply suggestions; security/rollback/test code needs evidence before deletion.
2. Run correctness/review pass.
3. Run security/threat-boundary pass and active adversarial tests.
4. Run static checks + deterministic fuzzing.
5. Run patch/rollback/manual-restore matrix on all real supplied archives.
6. Update version in PHP + `config.xml`, README and CHANGELOG.
7. Build clean `phappagebuilderguard/` ZIP.
8. Inspect ZIP file list and run `unzip -t`.
9. Verify no dev files or generated/runtime data are inside the release ZIP.
10. Run `tests/run_release_gate.sh` on that exact ZIP. The final stage must call `lozitax/ps-validator` and receive exit code `0` from the official PrestaShop Validator API.
11. Calculate SHA-256.
12. Do not call the release Validator-clean unless the exact final ZIP passed the Validator. A user's confirmed Validator result for the exact ZIP is also authoritative release evidence.

## Known intentional limits

- This Guard is a mitigation for legacy AP Page Builder. Upstream migration remains preferred.
- Scanner does not establish that an already compromised shop is clean.
- Theme overrides and root-level malware are intentionally outside this scanner's scope.
- Generic `.js`, `.css` and `.xml` writes remain allowed because real AP 2.4.1/2.4.3/2.4.5/2.4.8 code paths use them for profiles, positions, exports and custom assets. The Guard blocks server-side PHP/webshell content but is not a JavaScript/CSS malware interpreter.
- A multi-file patch is fail-safe per file and reports incomplete status if a later target fails. Do not add a transaction coordinator unless a real failure demonstrates that rollback orchestration is necessary.
