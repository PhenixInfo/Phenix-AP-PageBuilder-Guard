# Changelog

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
