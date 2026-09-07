# Development workspace — Phenix AP PageBuilder Guard

The `module/` directory is the exact module source used to build the Marketplace ZIP.
Development-only files live beside it and must never be packaged.

## Main gates

```bash
python3 tests/static_checks.py
python3 tests/fuzz_runtime.py
python3 tests/run_patch_matrix.py /path/to/ap-archives
```

## Official PrestaShop Validator

Install/update the CLI wrapper:

```bash
./tools/install_ps_validator.sh
```

Then export your personal Validator API key:

```bash
export PRESTASHOP_VALIDATOR_API_KEY="..."
```

Run the complete release gate against the **exact final ZIP**:

```bash
./tests/run_release_gate.sh ./phappagebuilderguard-1.1.16.zip /path/to/ap-archives ./reports/validator
```

The last stage uses `lozitax/ps-validator`, which uploads the ZIP to the official PrestaShop Validator API and requires exit code `0`.

`ps-validator` itself requires PHP 8.1+. This is only a development-tool requirement; the module runtime remains PHP 7.1+.

Without `PRESTASHOP_VALIDATOR_API_KEY` (or if the API/network fails), the release gate intentionally fails instead of silently marking the Validator step as skipped.
