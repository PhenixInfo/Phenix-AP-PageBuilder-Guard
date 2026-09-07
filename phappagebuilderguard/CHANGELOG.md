# Changelog

## 1.1.17 - 2026-09-07

- Added fail-safe patch compatibility for a real client AP Page Builder 2.4.8-derived hybrid using native `json_decode()` instead of `Tools::jsonDecode()` for the Base64 `config` path in `ApProductList.php`.
- Kept the insertion signature narrow: only the two observed equivalent decoders are accepted.
- Added the hybrid archive as an external regression case without redistributing third-party module code.
- No scanner scope expansion or runtime security relaxation.

## 1.1.16 - 2026-09-04

- Validator compliance only: restored the main PHP license comment immediately after `<?php` with no blank line before the file comment.
- No security or runtime logic change.

## 1.1.15 - 2026-09-04

- Conformité PrestaShop Validator / PHP CS Fixer sur `phappagebuilderguard.php`.
- Correction des séparations de classe, lignes vides après `<?php`, lignes vides superflues, lignes avant certains statements et fin de fichier.
- Aucun changement fonctionnel ou de logique sécurité.

## 1.1.14 - 2026-09-03

- Reduced false positives in the generic unknown-AJAX SQLi fallback: ordinary English phrases such as `Select from ...`, `Insert into ...`, `Delete from ...`, `Update from ...`, `Sleep (...)` and plain `1 and 1=1` are no longer sufficient to block by themselves.
- Kept high-confidence coverage for UNION SELECT, information_schema, OUTFILE/DUMPFILE, LOAD_FILE, stacked SQL statements, boolean extraction after SQL delimiters and context-bound SLEEP/BENCHMARK calls.
- Made the ApImageGallery guard case-insensitive as defense in depth, while the four tested upstream `apajax.php` files themselves compare the widget name case-sensitively.
- Rejected array/object `show_number` values before string conversion, avoiding PHP warnings while still blocking the request.
- Corrected stale documentation around the mandatory `_PRODUCTLIST_STORAGE_` markers and the quarantine feature removed in 1.1.12.
- Documented the expected upgrade behavior for shops patched by older Guard releases and the intentional `.js/.css/.xml` write allowance required by real AP Page Builder 2.4.1/2.4.3/2.4.5/2.4.8 code paths.

## 1.1.13 - 2026-09-03

- Hardened the targeted scanner against symlink escapes: symlink entries are skipped and every canonical file path is re-checked below `/modules/appagebuilder/` before reading.
- Rejected existing symlink targets in the generic AP Page Builder write guard.
- Removed the historical 4 KiB truncation from the high-confidence fallback for unknown AJAX SQLi parameters.
- Normalized SQL block comments and MySQL conditional comments before high-confidence SQLi matching, closing comment-obfuscation gaps without broad keyword blocking.
- Removed unused post-patch manifest generation, unused AP information fields, single-use helper wrappers and duplicate optional-file reads.
- Removed the runtime fallback that re-read `apajax.php` to infer token behavior; every Guard-generated patch already passes the detected token requirement explicitly.
- Expanded deterministic runtime/property tests to more than 800 cases, including every known numeric/list SQLi parameter, long-prefix and comment-obfuscated SQLi, 1 MiB benign input, symlink scope checks and Context-cookie path validation.
- Expanded the four-version patch matrix to verify exact manual-backup restoration in addition to pre-patch rollback.

## 1.1.12 - 2026-09-03

- Removed the quarantine/restore feature entirely; the targeted scanner is now strictly read-only.
- Removed quarantine runtime directories, BO actions, labels and snapshot/manifest code.
- Simplified scanner findings by removing constant severity/confidence plumbing.
- Inlined the single fixed scan root instead of keeping a one-item `getScanRoots()` abstraction.
- Simplified backup-directory initialization after quarantine removal.
- Removed the obsolete module-local log-directory fallback and its distributed `logs/` placeholder; runtime logs remain under `/var/phappagebuilderguard/logs/`.
- Added a separate development workspace with `AGENTS.md`, project skill adapters, static checks, deterministic runtime fuzzing and the four-version AP patch/rollback matrix. These development files are not included in the Marketplace ZIP.

## 1.1.11 - 2026-09-03

- Hardened `guardWriteFile()`: only AP Page Builder's expected `.tpl`, `.js`, `.css` and `.xml` writes are accepted; PHP/PHTML/unknown extensions and server configuration files such as `.htaccess` are rejected.
- Fixed the PrestaShop-root boundary comparison by requiring a normalized trailing separator.
- Made `guardApAjax()` checks cumulative so `leoajax=1` can no longer bypass gallery or Base64 `config` validation when multiple branch parameters are supplied.
- Expanded the documented numeric-parameter coverage and added a high-confidence generic SQLi fallback for unknown legacy AJAX parameters.
- Reduced request false positives: commercial strings such as `Pack (6 bouteilles)`, `Touch (Blue)` and `Copy (2024)` are no longer treated as Smarty/PHP droppers.
- Removed the hard requirement for `form_id` from Base64 config; missing/invalid identifiers now fall back safely instead of returning a 403.
- Removed the fallback to raw `$_COOKIE` for `product_item_path`; only the signed PrestaShop cookie is trusted.
- Made product-template path validation independent from the PHP current working directory and return the exact canonical path that was validated.
- Made `_PRODUCTLIST_STORAGE_` markers mandatory for patch-integrity status and fail-safe patch application.
- Tightened scanner signatures to high-confidence server-side patterns; native Smarty `{insert}` and ordinary inline JavaScript `copy()` are no longer critical findings.
- Reworked quarantine into reversible snapshots with SHA-256 manifests and an interface action to restore the latest quarantine.
- Hardened logs with a PHP-guarded `security.log.php`, legacy `security.log` reading support, filtered AP-specific payload fields plus a PHP execution guard in addition to `.htaccess`.
- Broadened the incomplete-patch back-office warning to the PrestaShop dashboard, AP Page Builder pages and the Guard configuration page.
- Expanded blocked AJAX JSON responses with `success`, `status`, `message` and legacy `hasError/errors` fields for better client compatibility.

## 1.1.10 - 2026-09-03

- Added a detailed explanation of the runtime protection layer in the Maintenance tab: when it runs, what it filters, what is logged and why it should normally remain enabled.
- Added full AFL-3.0 license headers to the Smarty templates.
- Adjusted PHP file headers so the file comment starts immediately after the PHP opening tag, as requested by the PrestaShop Validator license check.
- Added the AFL-3.0 metadata to the admin CSS header for consistency across source files.

## 1.1.9 - 2026-09-03

- Moved all back-office HTML rendering from PHP to Smarty templates, as required by the PrestaShop Validator.
- Added a dedicated local JavaScript file for confirmation dialogs instead of inline handlers.
- Added explicit AdminModules tokens to module forms.
- Applied the coding-standard fixes reported by the Validator: short array syntax, class-constant visibility, increment style, single quotes where applicable, `exit` instead of aliases, PHP opening/docblock spacing and blank lines before returns.
- Added protected index files to the new template and JavaScript directories.
- Kept the security and patching behaviour unchanged and revalidated patch/idempotence/rollback on AP Page Builder 2.4.1, 2.4.3, 2.4.5 and 2.4.8.

## 1.1.8 - 2026-09-03

- Added explicit AdminModules CSRF token validation for mutating back-office actions.
- Added atomic writes for patched files and atomic restores.
- Bounded request-payload inspection to reduce memory amplification on oversized requests.
- Added a maximum recursion depth for nested AP Page Builder configuration data.
- Added JSON serialization failure checks.
- Reduced repeated AP Page Builder file reads during version and patch-state detection.
- Stopped creating runtime backup/quarantine directories inside the module directory.
- Prevented automatic backup name collisions within the same second.
- Consolidated the admin stylesheet and removed superseded duplicate selectors.
- Added `.editorconfig` and explicit AFL-3.0 license metadata for community distribution.

## 1.1.7 - 2026-09-03

- Added complete PHP license tags required by the PrestaShop Validator.
