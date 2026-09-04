#!/usr/bin/env python3
# Development-only deterministic fuzz/regression tests for AP PageBuilder Guard.
# See AGENTS.md. Never package this file in the Marketplace ZIP.

import base64, json, os, pathlib, random, subprocess, sys, tempfile, time

ROOT = pathlib.Path(__file__).resolve().parents[1]
PHP_CASE = ROOT / 'tests/runtime_case.php'
SEED = 20260903
random.seed(SEED)

checks = 0
failures = []

def run(mode, payload, timeout=8):
    raw = base64.b64encode(json.dumps(payload).encode()).decode()
    cp = subprocess.run(['php', str(PHP_CASE), mode, raw], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    return cp.returncode, cp.stdout.strip(), cp.stderr.strip()

def expect(name, mode, payload, predicate, timeout=8):
    global checks
    checks += 1
    try:
        code, out, err = run(mode, payload, timeout=timeout)
        if not predicate(code, out, err):
            failures.append((name, code, out, err))
    except Exception as exc:
        failures.append((name, 'EXC', repr(exc), ''))

# Legitimate commercial values that used to false-positive.
for value in [
    'Pack (6 bouteilles)', 'Pack(3)', 'Touch (Blue)', 'Copy (2024)', 'Rename (nouveau)',
    'Kit complet (2 pieces)', 'Touchpad (sans fil)', 'copy (limited edition)', 'touch (cotton)',
    'rename (collection)', 'pack (family)', 'COPY (2025)', 'TOUCH (Pink)', 'RENAME (new)',
    'PACK (12)', 'Summer pack (6 items)', 'Copy (édition limitée)',
]:
    expect('commercial:' + value, 'ajax', {'get': {'leoajax': 1, 'label': value}}, lambda c,o,e: o == 'ALLOWED')

# Legitimate English/text values that contain SQL-ish words but are not SQL syntax.
for value in [
    'Select from our new collection',
    'Insert into your basket',
    'Delete from wishlist',
    'Update from supplier',
    'Sleep (Deluxe Edition)',
    'Matelas Sleep(200x200)',
    '1 and 1=1',
]:
    expect('sql-word-benign:' + value, 'ajax', {'get': {'leoajax': 1, 'future_label': value}}, lambda c,o,e: o == 'ALLOWED')

known_numeric = [
    'product_all_one_img','image_product','product_manufacture','product_one_img','leo_pro_cdown',
    'leo_pro_color','product_list_image','product_attribute_one_img','leo_pro_info','leo_pro_add','list_cat',
    'cat_list','categorybox','manufacture','supplier','product_id','manuselect','wishlist_compare',
    'id_product','id_product_attribute','id_category'
]
malicious_variants = [
    '1) or 1=1#',
    '1/**/OR/**/1=1#',
    '1/*!50000OR*/1=1#',
    'if(now()=sysdate(),sleep(6),0)',
    '-1234) OR 6644=6644-- yMwI',
    '1)/**/or/**/ord(mid((select table_name from information_schema.tables limit 1),1,1))>50#',
]
for key in known_numeric:
    for value in malicious_variants:
        expect('known-sqli:%s:%s' % (key, value[:10]), 'ajax', {'get': {'leoajax': 1, key: value}}, lambda c,o,e: o.startswith('BLOCKED:'))

# Unknown-key high confidence coverage and false positive controls.
unknown_attacks = [
    '0 UNION SELECT password FROM employee',
    'abc information_schema.tables',
    '1) or sleep(3)#',
    "x') INTO OUTFILE '/tmp/x'--",
    '1; SELECT 1',
    '0) or ord(mid((select database()),1,1))>50#',
    '0) or (select count(*) from information_schema.tables)>1#',
    "1) or load_file('/etc/passwd') is not null#",
    '1)/**/UNION/**/SELECT/**/1,2,3#',
    '1/*!50000UNION*/ /*!50000SELECT*/ 1,2,3#',
]
for value in unknown_attacks:
    expect('unknown-sqli:' + value[:20], 'ajax', {'get': {'leoajax': 1, 'future_param': value}}, lambda c,o,e: o.startswith('BLOCKED:'))

# Long-prefix regressions: malicious syntax must be seen beyond old 4 KiB boundaries.
for n in [4095, 4096, 5000, 16000]:
    value = ('A' * n) + ' 0 UNION SELECT password FROM employee'
    expect('long-prefix-%d' % n, 'ajax', {'get': {'leoajax': 1, 'future_param': value}}, lambda c,o,e: o.startswith('BLOCKED:'))

# Generated 1 MiB benign value: complete-value SQLi inspection must remain practical.
start = time.monotonic()
expect('large-benign-1mib', 'ajax', {'generated_unknown_len': 1024 * 1024}, lambda c,o,e: o == 'ALLOWED', timeout=12)
large_elapsed = time.monotonic() - start
if large_elapsed > 3.0:
    failures.append(('large-benign-performance', 0, '%.3fs' % large_elapsed, 'expected <= 3s in local harness'))

# Mutate SQL spacing/case/comments deterministically.
keywords = [('union','select'), ('or','sleep'), ('or','benchmark')]
for i in range(250):
    k1, k2 = random.choice(keywords)
    def mutate(word):
        return ''.join(ch.upper() if random.randrange(2) else ch.lower() for ch in word)
    sep = random.choice([' ', '  ', '/**/', '/*x*/', '\t', '\n'])
    if k1 == 'union':
        value = '0 ' + mutate(k1) + sep + mutate(k2) + ' 1,2,3#'
    else:
        value = '0) ' + mutate(k1) + sep + mutate(k2) + '(2)#'
    expect('mutation-%03d' % i, 'ajax', {'get': {'leoajax': 1, 'future_mut': value}}, lambda c,o,e: o.startswith('BLOCKED:'))

# F2 regression: checks must be cumulative.
expect('leoajax+gallery', 'ajax', {'get': {'leoajax': 1, 'widget': 'ApImageGallery', 'show_number': '<script>x</script>'}}, lambda c,o,e: o.startswith('BLOCKED:'))
for widget in ['apimagegallery', 'APIMAGEGALLERY', 'ApImageGallery']:
    expect('gallery-case:' + widget, 'ajax', {'get': {'widget': widget, 'show_number': '<script>x</script>'}}, lambda c,o,e: o.startswith('BLOCKED:'))
expect('gallery-array-no-warning', 'ajax', {'get': {'widget': 'ApImageGallery', 'show_number': [5]}}, lambda c,o,e: o.startswith('BLOCKED:') and 'Array to string conversion' not in e and 'Warning' not in e)
traversal_cfg = base64.b64encode(json.dumps({'product_item_path':'../../../../etc/passwd','columns':1}).encode()).decode()
expect('leoajax+config', 'ajax', {'get': {'leoajax': 1, 'config': traversal_cfg}}, lambda c,o,e: o.startswith('BLOCKED:'))

# Missing form_id is accepted when config is otherwise safe.
safe_cfg = base64.b64encode(json.dumps({'product_item_path':'catalog/_partials/miniatures/product.tpl','columns':1}).encode()).decode()
expect('missing-form-id', 'ajax', {'get': {'config': safe_cfg}}, lambda c,o,e: o == 'ALLOWED')

# Obfuscated/noisy base64 traversal.
for noise in ['$', '-', '#', ' ', '\n']:
    noisy = traversal_cfg[:8] + noise + traversal_cfg[8:]
    expect('base64-noise:' + repr(noise), 'ajax', {'get': {'config': noisy}}, lambda c,o,e: o.startswith('BLOCKED:'))

# Generic writes.
with tempfile.TemporaryDirectory(prefix='phapb-write-') as tmp:
    root = pathlib.Path(tmp)
    allowed_dir = root/'modules/appagebuilder/views/templates/gen'
    allowed_dir.mkdir(parents=True)
    for ext in ['tpl','js','css','xml']:
        expect('write-allowed-' + ext, 'write', {'root': str(root), 'target': str(allowed_dir/('ok.'+ext)), 'content': 'safe content'}, lambda c,o,e: o == 'ALLOWED')
    for name in ['shell.php','x.phtml','.htaccess','.user.ini','php.ini','web.config','foo.exe','x.php.jpg']:
        expect('write-forbidden-' + name, 'write', {'root': str(root), 'target': str(allowed_dir/name), 'content': '<?php eval($_POST["x"]);'}, lambda c,o,e: o.startswith('BLOCKED:'))
    expect('root-sibling', 'write', {'root': str(root), 'target': str(pathlib.Path(str(root)+'EVIL')/'x.tpl'), 'content': 'safe'}, lambda c,o,e: o.startswith('BLOCKED:'))
    outside = root/'outside.tpl'; outside.write_text('outside')
    symlink_target = allowed_dir/'linked.tpl'; symlink_target.symlink_to(outside)
    expect('write-symlink-target', 'write', {'root': str(root), 'target': str(symlink_target), 'content': 'safe'}, lambda c,o,e: o.startswith('BLOCKED:'))

# Scanner must not follow symlinks outside module scope.
with tempfile.TemporaryDirectory(prefix='phapb-scan-') as tmp:
    root = pathlib.Path(tmp)
    module = root/'modules/appagebuilder'
    module.mkdir(parents=True)
    (module/'legit.tpl').write_text('plain template')
    outside = root/'outside.php'; outside.write_text('<?php eval(base64_decode($_POST["x"]));')
    (module/'outside-link.php').symlink_to(outside)
    outside_dir = root/'outside-dir'; outside_dir.mkdir(); (outside_dir/'evil.php').write_text('<?php eval(base64_decode($_POST["x"]));')
    (module/'outside-dir-link').symlink_to(outside_dir, target_is_directory=True)
    expect('scanner-symlink-boundary', 'scan', {'root': str(root)}, lambda c,o,e: 'outside-link.php' not in o and 'outside-dir-link' not in o and 'outside.php' not in o)

# Raw client cookie is deliberately ignored. Context cookie gets canonical validation.
with tempfile.TemporaryDirectory(prefix='phapb-cookie-') as tmp:
    root = pathlib.Path(tmp)
    valid_dir = root/'modules/appagebuilder/views/templates/front/product-item'; valid_dir.mkdir(parents=True)
    valid = valid_dir/'item.tpl'; valid.write_text('ok')
    expect('raw-cookie-ignored', 'path', {'root': str(root), 'form_id':'42', 'cookie': {'appagebuilder_product_item_path_42': str(valid)}}, lambda c,o,e: o == 'catalog/_partials/miniatures/product.tpl')
    expect('context-cookie-valid', 'path', {'root': str(root), 'form_id':'42', 'context_cookie': {'appagebuilder_product_item_path_42': str(valid)}}, lambda c,o,e: o == str(valid.resolve()))

# Logging whitelist/redaction smoke test.
with tempfile.TemporaryDirectory(prefix='phapb-log-') as tmp:
    expect('log-filter-redact', 'log', {'root': tmp, 'get': {'leoajax':'1','token':'SECRET','mail':'a@b.c','id_customer':'77','product_one_img':'1'}}, lambda c,o,e: '[REDACTED]' in o and 'a@b.c' not in o and 'id_customer' not in o)

if failures:
    for item in failures[:30]:
        print('FAIL', item)
    print('FAILED: %d/%d checks (seed=%d)' % (len(failures), checks, SEED))
    sys.exit(1)
print('fuzz/runtime: OK %d checks (seed=%d, large=%.3fs)' % (checks, SEED, large_elapsed))
