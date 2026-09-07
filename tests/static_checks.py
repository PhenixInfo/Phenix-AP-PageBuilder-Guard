#!/usr/bin/env python3
import pathlib, re, sys, xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1] / 'module'
errors = []
php_files = list(ROOT.rglob('*.php'))
for p in php_files:
    s = p.read_text(errors='strict')
    if not (s.startswith('<?php\n/**') or s.startswith('<?php\n\n/**')):
        errors.append('%s: unexpected PHP file header/docblock placement' % p.relative_to(ROOT))
    for token in ['@author', '@copyright', '@license']:
        if token not in s[:1000]:
            errors.append('%s: missing %s' % (p.relative_to(ROOT), token))

for p in list(ROOT.rglob('*.tpl')):
    s = p.read_text(errors='strict')
    if '@license' not in s[:1000]:
        errors.append('%s: missing template license header' % p.relative_to(ROOT))
    for match in re.finditer(r'\{\$[^}]+\}', s):
        if '|escape' not in match.group(0):
            errors.append('%s: unescaped Smarty output: %s' % (p.relative_to(ROOT), match.group(0)[:120]))

main = (ROOT / 'phappagebuilderguard.php').read_text()
if not main.startswith('<?php\n/**'):
    errors.append('phappagebuilderguard.php: license header must immediately follow <?php with no blank line')
if '\n\n        } catch (Exception $e)' in main:
    errors.append('phappagebuilderguard.php: no_extra_blank_lines regression before catch')
if re.search(r'\n    }\n\n}\n?$', main):
    errors.append('phappagebuilderguard.php: class_attributes_separation/extra blank line before class close')
if not main.endswith('}\n') or main.endswith('}\n\n'):
    errors.append('phappagebuilderguard.php: single_blank_line_at_eof regression')
for rule in ['class_attributes_separation', 'no_extra_blank_lines', 'blank_line_before_statement', 'single_blank_line_at_eof']:
    if rule not in (ROOT.parent / 'AGENTS.md').read_text(errors='strict'):
        errors.append('AGENTS.md missing learned Validator rule: %s' % rule)
config = ET.parse(ROOT / 'config.xml').getroot()
version_php = re.search(r"\$this->version\s*=\s*'([^']+)'", main).group(1)
desc_php = re.search(r"\$this->description\s*=\s*\$this->l\('([^']+)'\)", main).group(1)
version_xml = config.findtext('version')
desc_xml = config.findtext('description')
if version_php != version_xml:
    errors.append('version mismatch PHP=%s XML=%s' % (version_php, version_xml))
if desc_php != desc_xml:
    errors.append('description mismatch PHP/XML')

if re.search(r"(?:return|\$html\s*\.?=).*<\s*(?:div|form|table|section|article|span|a)\b", main, re.I):
    errors.append('HTML rendering found in phappagebuilderguard.php; use Smarty')

if (ROOT / 'quarantine').exists() or 'phapb_quarantine' in main:
    errors.append('quarantine/remediation must not be in this module')

core = (ROOT / 'classes/PhApPageBuilderGuard.php').read_text()
if 'getScanRoots' in core:
    errors.append('obsolete getScanRoots abstraction returned; scanner has one fixed root')
if "_PS_MODULE_DIR_ . 'appagebuilder/'" not in core:
    errors.append('targeted scanner root invariant missing')

if 'isLink()' not in core or 'realpath($fileInfo->getPathname())' not in core:
    errors.append('scanner symlink/canonical boundary guard missing')
if 'is_link($target)' not in core:
    errors.append('generic write symlink target guard missing')
if 'writePatchManifest' in main:
    errors.append('unused post-patch manifest writer returned')
for obsolete in ['apgencode_pattern', 'product_path_cookie', 'getBackupRelativeName', 'getApPageBuilderVersion']:
    if obsolete in main:
        errors.append('obsolete/dead symbol returned: %s' % obsolete)

all_php = '\n'.join(p.read_text(errors='strict') for p in php_files)
for match in re.finditer(r'private\s+(?:static\s+)?function\s+(\w+)\s*\(', all_php):
    name = match.group(1)
    if len(re.findall(r'\b' + re.escape(name) + r'\b', all_php)) < 2:
        errors.append('dead private method: %s' % name)

workspace = ROOT.parent
agents = (workspace / 'AGENTS.md').read_text(errors='strict')
if 'License-header precedence for the main module file' not in agents:
    errors.append('AGENTS.md missing main-file Validator license-header precedence rule')
for required in ['lozitax/ps-validator', 'PRESTASHOP_VALIDATOR_API_KEY', 'tests/run_ps_validator.sh', 'tests/run_release_gate.sh']:
    if required not in agents:
        errors.append('AGENTS.md missing mandatory Validator gate reference: %s' % required)
for required_file in [workspace / 'tests/run_ps_validator.sh', workspace / 'tests/run_release_gate.sh', workspace / 'tools/install_ps_validator.sh']:
    if not required_file.exists():
        errors.append('missing required release tool: %s' % required_file.relative_to(workspace))

if errors:
    print('\n'.join('FAIL: ' + e for e in errors))
    sys.exit(1)
print('static checks: OK (%d PHP files)' % len(php_files))
