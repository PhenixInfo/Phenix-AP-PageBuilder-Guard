<?php
/**
 * Runtime protection engine for AP Page Builder.
 *
 * Methods are static because patched AP Page Builder files call this class
 * directly before executing vulnerable legacy code paths.
 *
 * @author Phenix Info
 * @copyright 2026 Phenix Info
 * @license https://opensource.org/licenses/AFL-3.0 Academic Free License version 3.0
 */
if (!defined('_PS_VERSION_')) {
    exit;
}

class PhApPageBuilderGuardCore
{
    public const CONFIG_ENABLED = 'PHAPB_GUARD_ENABLED';
    public const LOG_FILE = 'security.log';
    public const MAX_LOG_BYTES = 2097152;
    public const MAX_LOG_FILES = 3;
    public const MAX_LOG_VALUE = 1024;
    public const MAX_LOG_PAYLOAD = 4096;
    public const MAX_INSPECTION_VALUE = 4096;
    public const MAX_INSPECTION_TOTAL = 16384;
    public const MAX_CONFIG_DEPTH = 32;

    public static function guardApAjax($tokenRequired = null)
    {
        if (!self::isEnabled()) {
            return;
        }

        self::guardCommonRequestPayload();

        // Certaines branches historiques (2.2 / 2.3 / debut 2.4) ne valident
        // pas le token de la meme maniere. On reproduit le niveau de controle
        // du fichier apajax.php installe pour eviter les faux positifs.
        if ($tokenRequired === null) {
            $tokenRequired = self::apAjaxUsesTokenCheck();
        }

        if ((string) self::getRequestValue('action') === 'get-product-link') {
            return;
        }

        if (self::getRequestValue('leoajax') == 1) {
            if ($tokenRequired && (!class_exists('Tools') || Tools::getToken(false) !== (string) self::getRequestValue('token'))) {
                self::block('token AJAX invalide');
            }
            self::sanitizeAjaxIntegerParameters();
            self::guardShortcodeAjax();

            return;
        }

        if ((string) self::getRequestValue('widget') === 'ApImageGallery') {
            self::guardImageGalleryAjax();

            return;
        }

        if (self::getRequestValue('config') !== null && self::getRequestValue('config') !== '') {
            self::sanitizeConfigRequest();

            return;
        }

        // Compatibilite : les branches 2.2 a 2.4.9 ne possedent pas toutes les
        // memes actions. Une action inconnue n'est donc pas bloquee par principe.
    }

    public static function guardWriteFile($targetFile, $value)
    {
        if (!self::isEnabled()) {
            return;
        }

        $target = str_replace('\\', '/', (string) $targetFile);
        if ($target === '' || strpos($target, "\0") !== false || preg_match('#(^|/)\.\.(/|$)#', $target)) {
            self::throwBlock('chemin ecriture interdit', $target);
        }

        $dir = dirname($target);
        $realDir = realpath($dir);
        if ($realDir === false) {
            self::throwBlock('repertoire ecriture introuvable', $target);
        }

        $root = realpath(_PS_ROOT_DIR_);
        if ($root !== false && strpos(str_replace('\\', '/', $realDir), str_replace('\\', '/', $root)) !== 0) {
            self::throwBlock('ecriture hors racine PrestaShop', $target);
        }

        $extension = strtolower(pathinfo($target, PATHINFO_EXTENSION));
        if ($extension === 'tpl') {
            $base = basename($target);
            if (!preg_match('/^[a-zA-Z0-9_.-]+\.tpl$/', $base)) {
                self::throwBlock('nom de template non autorise', $target);
            }
            self::assertSafeSmartyTemplate((string) $value, $target);
        }
    }

    public static function guardGeneratedTemplate($folder, $file, $value)
    {
        if (!self::isEnabled()) {
            return;
        }

        $folder = rtrim(str_replace('\\', '/', (string) $folder), '/');
        $file = str_replace('\\', '/', (string) $file);
        if ($file === '' || basename($file) !== $file || strtolower(pathinfo($file, PATHINFO_EXTENSION)) !== 'tpl') {
            self::throwBlock('nom ApGenCode interdit', $file);
        }

        self::guardWriteFile($folder . '/' . $file, $value);
    }

    public static function sanitizeApProductListInput($input)
    {
        if (!self::isEnabled()) {
            return $input;
        }

        if (!is_object($input)) {
            self::block('config produit invalide');
        }

        $array = json_decode(json_encode($input), true);
        if (!is_array($array)) {
            self::block('config produit JSON invalide');
        }

        $array = self::sanitizeProductListConfigArray($array);
        $json = json_encode($array);
        $clean = json_decode($json);
        if (!is_object($clean)) {
            self::block('config produit invalide apres nettoyage');
        }

        return $clean;
    }

    public static function getSafeProductItemPath($formId)
    {
        if (!self::isEnabled()) {
            $cookieName = 'productItemPathApProductList_' . $formId;

            return isset(Context::getContext()->cookie->{$cookieName}) ? Context::getContext()->cookie->{$cookieName} : 'catalog/_partials/miniatures/product.tpl';
        }

        $formId = (string) $formId;
        if (!preg_match('/^[a-zA-Z0-9_-]{1,80}$/', $formId)) {
            self::block('form_id produit invalide');
        }

        $cookieName = 'productItemPathApProductList_' . $formId;
        $path = null;
        if (isset(Context::getContext()->cookie->{$cookieName})) {
            $path = Context::getContext()->cookie->{$cookieName};
        } elseif (isset($_COOKIE[$cookieName])) {
            $path = $_COOKIE[$cookieName];
        }

        if (is_string($path) && self::isSafeProductTemplatePath($path)) {
            return $path;
        }

        if (is_string($path) && $path !== '') {
            self::logEvent('product_item_path_rejected', 'Chemin refuse : ' . $path);
        }

        return 'catalog/_partials/miniatures/product.tpl';
    }

    public static function scanInstallation()
    {
        $findings = [];
        foreach (self::getScanRoots() as $root) {
            if (!is_dir($root)) {
                continue;
            }
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
            );
            foreach ($iterator as $fileInfo) {
                if (!$fileInfo->isFile()) {
                    continue;
                }
                self::scanOneFile($fileInfo->getPathname(), $findings);
            }
        }

        return $findings;
    }

    public static function logEvent($type, $message)
    {
        $dir = self::getLogDir();
        if (!self::ensurePrivateDirectory($dir)) {
            return false;
        }

        $log = $dir . '/' . self::LOG_FILE;
        self::rotateLogs($log);

        $entry = [
            'date' => date('c'),
            'event' => self::cleanLogString($type, 80),
            'reason' => self::cleanLogString($message, 1500),
            'ip' => self::getClientIp(),
            'method' => isset($_SERVER['REQUEST_METHOD']) ? self::cleanLogString($_SERVER['REQUEST_METHOD'], 12) : 'CLI',
            'url' => self::getSafeRequestUrl(),
            'payload' => self::getSafePayload(),
        ];

        $forwarded = self::getUntrustedForwardedIp();
        if ($forwarded !== '') {
            // Information utile derriere un proxy, mais volontairement non traitee
            // comme IP de confiance car cet en-tete peut etre usurpe.
            $entry['forwarded_for_untrusted'] = $forwarded;
        }

        $line = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($line === false) {
            return false;
        }

        $ok = @file_put_contents($log, $line . PHP_EOL, FILE_APPEND | LOCK_EX);
        if ($ok !== false) {
            @chmod($log, 0600);

            return true;
        }

        return false;
    }

    public static function getRecentLogEntries($limit = 100)
    {
        $limit = max(1, min(250, (int) $limit));
        $dir = self::getLogDir();
        $entries = [];
        $files = [$dir . '/' . self::LOG_FILE];
        for ($i = 1; $i <= self::MAX_LOG_FILES; ++$i) {
            $files[] = $dir . '/' . self::LOG_FILE . '.' . $i;
        }

        foreach ($files as $file) {
            if (!is_file($file) || !is_readable($file)) {
                continue;
            }
            foreach (self::readLogTail($file, $limit - count($entries)) as $entry) {
                $entries[] = $entry;
                if (count($entries) >= $limit) {
                    break 2;
                }
            }
        }

        usort($entries, [__CLASS__, 'sortLogEntriesNewestFirst']);

        return array_slice($entries, 0, $limit);
    }

    public static function clearLogs()
    {
        $dir = self::getLogDir();
        $removed = 0;
        for ($i = 0; $i <= self::MAX_LOG_FILES; ++$i) {
            $file = $dir . '/' . self::LOG_FILE . ($i ? '.' . $i : '');
            if (is_file($file) && @unlink($file)) {
                ++$removed;
            }
        }
        return $removed;
    }

    public static function getLogInfo()
    {
        $dir = self::getLogDir();
        $bytes = 0;
        $files = 0;
        for ($i = 0; $i <= self::MAX_LOG_FILES; ++$i) {
            $file = $dir . '/' . self::LOG_FILE . ($i ? '.' . $i : '');
            if (is_file($file)) {
                ++$files;
                $size = @filesize($file);
                if ($size !== false) {
                    $bytes += (int) $size;
                }
            }
        }
        return ['path' => $dir . '/' . self::LOG_FILE, 'bytes' => $bytes, 'files' => $files];
    }

    private static function getLogDir()
    {
        if (defined('_PS_ROOT_DIR_')) {
            return rtrim(_PS_ROOT_DIR_, '/\\') . '/var/phappagebuilderguard/logs';
        }
        return dirname(dirname(__FILE__)) . '/logs';
    }

    private static function ensurePrivateDirectory($dir)
    {
        if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
            return false;
        }
        @chmod($dir, 0750);

        $htaccess = $dir . '/.htaccess';
        if (!is_file($htaccess)) {
            @file_put_contents($htaccess, "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
            @chmod($htaccess, 0600);
        }
        $index = $dir . '/index.php';
        if (!is_file($index)) {
            @file_put_contents($index, "<?php\nexit;\n");
            @chmod($index, 0600);
        }

        return true;
    }

    private static function rotateLogs($log)
    {
        if (!is_file($log)) {
            return;
        }
        $size = @filesize($log);
        if ($size === false || $size < self::MAX_LOG_BYTES) {
            return;
        }

        $last = $log . '.' . self::MAX_LOG_FILES;
        if (is_file($last)) {
            @unlink($last);
        }
        for ($i = self::MAX_LOG_FILES - 1; $i >= 1; --$i) {
            $src = $log . '.' . $i;
            $dst = $log . '.' . ($i + 1);
            if (is_file($src)) {
                @rename($src, $dst);
            }
        }
        @rename($log, $log . '.1');
    }

    private static function readLogTail($file, $limit)
    {
        if ($limit <= 0) {
            return [];
        }
        $handle = @fopen($file, 'rb');
        if (!$handle) {
            return [];
        }

        $size = @filesize($file);
        $window = 262144;
        if ($size !== false && $size > $window) {
            @fseek($handle, -$window, SEEK_END);
            @fgets($handle); // ignore la premiere ligne potentiellement tronquee
        }

        $lines = [];
        while (($line = fgets($handle)) !== false) {
            $line = trim($line);
            if ($line !== '') {
                $lines[] = $line;
            }
        }
        fclose($handle);

        $lines = array_slice($lines, -$limit);
        $lines = array_reverse($lines);
        $entries = [];
        foreach ($lines as $line) {
            $entry = json_decode($line, true);
            if (is_array($entry)) {
                $entries[] = $entry;
            }
        }
        return $entries;
    }

    private static function sortLogEntriesNewestFirst($a, $b)
    {
        $da = isset($a['date']) ? (string) $a['date'] : '';
        $db = isset($b['date']) ? (string) $b['date'] : '';
        if ($da === $db) {
            return 0;
        }
        return ($da > $db) ? -1 : 1;
    }

    private static function getClientIp()
    {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? trim((string) $_SERVER['REMOTE_ADDR']) : '';
        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
        return self::cleanLogString($ip, 64);
    }

    private static function getUntrustedForwardedIp()
    {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP'] as $key) {
            if (!empty($_SERVER[$key])) {
                return self::cleanLogString($_SERVER[$key], 256);
            }
        }
        return '';
    }

    private static function getSafeRequestUrl()
    {
        $uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';
        if ($uri === '') {
            return '';
        }

        $parts = @parse_url($uri);
        if (!is_array($parts)) {
            return self::cleanLogString($uri, 2048);
        }
        $path = isset($parts['path']) ? self::cleanLogString($parts['path'], 1200) : '';
        if (empty($parts['query'])) {
            return $path;
        }

        $query = [];
        parse_str($parts['query'], $query);
        $query = self::sanitizeLogValue($query, 0);
        $qs = http_build_query($query, '', '&');

        return self::cleanLogString($path . ($qs !== '' ? '?' . $qs : ''), 2048);
    }

    private static function getSafePayload()
    {
        $payload = [];
        if (!empty($_GET)) {
            $payload['get'] = self::sanitizeLogValue($_GET, 0);
        }
        if (!empty($_POST)) {
            $payload['post'] = self::sanitizeLogValue($_POST, 0);
        }

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json !== false && strlen($json) > self::MAX_LOG_PAYLOAD) {
            return ['_truncated' => substr($json, 0, self::MAX_LOG_PAYLOAD) . '...'];
        }
        return $payload;
    }

    private static function sanitizeLogValue($value, $depth, $key = '')
    {
        if (self::isSensitiveLogKey($key)) {
            return '[REDACTED]';
        }
        if ($depth >= 3) {
            return '[MAX_DEPTH]';
        }
        if (is_array($value)) {
            $clean = [];
            $count = 0;
            foreach ($value as $k => $v) {
                if ($count++ >= 30) {
                    $clean['_truncated'] = true;

                    break;
                }
                $safeKey = self::cleanLogString($k, 80);
                $clean[$safeKey] = self::sanitizeLogValue($v, $depth + 1, (string) $k);
            }
            return $clean;
        }
        if (is_object($value)) {
            return '[OBJECT]';
        }
        if (is_bool($value) || is_int($value) || is_float($value) || $value === null) {
            return $value;
        }
        return self::cleanLogString($value, self::MAX_LOG_VALUE);
    }

    private static function isSensitiveLogKey($key)
    {
        return (bool) preg_match('/(?:pass(?:word|wd)?|token|authorization|cookie|session|secret|api[_-]?key|access[_-]?token|csrf|passwd|card[_-]?(?:number|no)|credit[_-]?card|cvv|cvc|iban)/i', (string) $key);
    }

    private static function cleanLogString($value, $max)
    {
        $value = (string) $value;
        $value = preg_replace('/[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]/', '', $value);
        $value = str_replace(["\r", "\n"], ' ', $value);
        if (strlen($value) > $max) {
            $value = substr($value, 0, $max) . '...';
        }
        return $value;
    }

    private static function apAjaxUsesTokenCheck()
    {
        if (!defined('_PS_MODULE_DIR_')) {
            return false;
        }
        $file = _PS_MODULE_DIR_ . 'appagebuilder/apajax.php';
        $content = @file_get_contents($file);
        if (!is_string($content) || $content === '') {
            return false;
        }
        return (bool) preg_match("/Tools::getToken\\s*\\(\\s*false\\s*\\)[^\\n]{0,180}Tools::getValue\\s*\\(\\s*[\'\"]token[\'\"]\\s*\\)|Tools::getValue\\s*\\(\\s*[\'\"]token[\'\"]\\s*\\)[^\\n]{0,180}Tools::getToken\\s*\\(\\s*false\\s*\\)/i", $content);
    }

    private static function isEnabled()
    {
        if (!class_exists('Configuration')) {
            return true;
        }

        return (bool) Configuration::get(self::CONFIG_ENABLED);
    }

    /**
     * Inspecte un echantillon borne de la requete afin d eviter de dupliquer en
     * memoire un POST ou un cookie anormalement volumineux.
     */
    private static function guardCommonRequestPayload()
    {
        $joined = '';
        foreach ([$_GET, $_POST, $_COOKIE] as $bucket) {
            foreach ($bucket as $key => $value) {
                $flat = self::flattenValue($value, self::MAX_INSPECTION_VALUE);
                $joined .= ' ' . substr((string) $key, 0, 128) . '=' . $flat;
                if (strlen($joined) >= self::MAX_INSPECTION_TOTAL) {
                    $joined = substr($joined, 0, self::MAX_INSPECTION_TOTAL);
                    break 2;
                }
            }
        }

        if (self::looksLikeSmartyDropper($joined) || self::looksLikePhpWebshell($joined)) {
            self::block('payload webshell/dropper detecte');
        }
    }

    private static function sanitizeAjaxIntegerParameters()
    {
        $intListKeys = [
            'cat_list',
            'product_list_image',
            'product_one_img',
            'product_attribute_one_img',
            'product_all_one_img',
            'pro_cdown',
            'pro_color',
            'leo_pro_cdown',
            'leo_pro_color',
            'leo_pro_info',
            'leo_pro_add',
            'product_size',
            'product_attribute',
            'product_manufacture',
            'image_product',
        ];

        foreach ($intListKeys as $key) {
            $value = self::getRequestValue($key);
            if ($value === null || $value === '') {
                continue;
            }
            self::setRequestValue($key, self::sanitizeIntList($value, $key));
        }
    }

    private static function guardShortcodeAjax()
    {
        foreach (['tabshortcode', 'tabshortcodekey'] as $key) {
            $value = self::getRequestValue($key);
            if ($value === null || $value === '') {
                continue;
            }
            $decoded = urldecode((string) $value);
            if (self::looksLikeSmartyDropper($decoded) || self::looksLikePhpWebshell($decoded) || self::hasTraversalOrWrapper($decoded)) {
                self::block('shortcode AJAX suspect');
            }
        }
    }

    private static function guardImageGalleryAjax()
    {
        $rawShowNumber = self::getRequestValue('show_number');
        if ($rawShowNumber === null || $rawShowNumber === '' || !preg_match('/^\d{1,3}$/', (string) $rawShowNumber)) {
            self::block('show_number galerie invalide');
        }
        $showNumber = (int) $rawShowNumber;
        if ($showNumber < 0 || $showNumber > 500) {
            self::block('show_number galerie invalide');
        }
        // Le code AP Page Builder historique relit ensuite Tools::getValue().
        // On remplace donc la valeur brute par l entier valide, au lieu de se
        // contenter d un cast local qui laisserait le payload original intact.
        self::setRequestValue('show_number', (string) $showNumber);

        $assign = self::getRequestValue('assign');
        if (!is_string($assign) || $assign === '') {
            self::block('assign galerie manquant');
        }

        $decoded = json_decode($assign, true);
        if (!is_array($decoded) || !isset($decoded['formAtts']) || !is_array($decoded['formAtts'])) {
            self::block('assign galerie invalide');
        }

        $path = isset($decoded['formAtts']['path']) ? (string) $decoded['formAtts']['path'] : '';
        if ($path === '' || self::hasTraversalOrWrapper($path)) {
            self::block('chemin galerie interdit');
        }

        $decoded['formAtts']['limit'] = isset($decoded['formAtts']['limit']) ? max(1, min(200, (int) $decoded['formAtts']['limit'])) : 20;
        $decoded['formAtts']['columns'] = isset($decoded['formAtts']['columns']) ? max(1, min(12, (int) $decoded['formAtts']['columns'])) : 4;
        $assignJson = json_encode($decoded);
        if ($assignJson === false) {
            self::block('assign galerie non serialisable');
        }
        self::setRequestValue('assign', $assignJson);
    }

    private static function sanitizeConfigRequest()
    {
        $raw = self::getRequestValue('config');
        if (!is_string($raw) || $raw === '') {
            self::block('config absente');
        }

        $decoded = self::decodeBase64Loose($raw);
        if ($decoded === false || $decoded === '') {
            self::block('config base64 invalide');
        }

        if (self::looksLikeSmartyDropper($decoded) || self::looksLikePhpWebshell($decoded) || self::hasTraversalOrWrapper($decoded)) {
            self::block('config dangereuse');
        }

        $data = json_decode($decoded, true);
        if (!is_array($data)) {
            self::block('config JSON invalide');
        }

        $data = self::sanitizeProductListConfigArray($data);
        $json = json_encode($data);
        if ($json === false) {
            self::block('config JSON non serialisable');
        }
        self::setRequestValue('config', base64_encode($json));
    }

    private static function sanitizeProductListConfigArray(array $data)
    {
        if (isset($data['product_item_path'])) {
            self::block('product_item_path interdit dans config');
        }

        if (isset($data['form_id'])) {
            $data['form_id'] = (string) $data['form_id'];
            if (!preg_match('/^[a-zA-Z0-9_-]{1,80}$/', $data['form_id'])) {
                self::block('form_id invalide');
            }
        } else {
            self::block('form_id manquant');
        }

        foreach (['nb_products', 'page_number', 'columns', 'limit'] as $key) {
            if (isset($data[$key])) {
                $data[$key] = max(1, min(120, (int) $data[$key]));
            }
        }

        foreach (['value_by_categories', 'value_by_product_type', 'value_by_manufacture', 'value_by_supplier', 'value_by_product_id', 'use_showmore'] as $key) {
            if (isset($data[$key])) {
                $data[$key] = (int) (bool) $data[$key];
            }
        }

        foreach (['categorybox', 'manufacture', 'supplier', 'product_id', 'manuselect'] as $key) {
            if (isset($data[$key])) {
                $data[$key] = self::sanitizeIntList($data[$key], $key);
            }
        }

        if (isset($data['order_by'])) {
            $allowed = ['position', 'name', 'price', 'id_product', 'date_add', 'date_upd', 'reference', 'manufacturer', 'quantity'];
            $data['order_by'] = in_array((string) $data['order_by'], $allowed, true) ? (string) $data['order_by'] : 'position';
        }

        if (isset($data['order_way'])) {
            $way = strtolower((string) $data['order_way']);
            $data['order_way'] = in_array($way, ['asc', 'desc', 'random'], true) ? ($way === 'random' ? 'random' : strtoupper($way)) : 'ASC';
        }

        if (isset($data['product_type'])) {
            $allowedTypes = ['all', 'new_product', 'best_sellers', 'price_drop', 'home_featured'];
            $data['product_type'] = in_array((string) $data['product_type'], $allowedTypes, true) ? (string) $data['product_type'] : 'all';
        }

        if (isset($data['category_type'])) {
            $allowedCategoryTypes = ['all', 'default'];
            $data['category_type'] = in_array((string) $data['category_type'], $allowedCategoryTypes, true) ? (string) $data['category_type'] : 'all';
        }

        foreach (['profile', 'override_folder'] as $key) {
            if (isset($data[$key])) {
                $data[$key] = (string) $data[$key];
                if ($data[$key] !== '' && $data[$key] !== 'default' && !preg_match('/^[a-zA-Z0-9_-]{1,80}$/', $data[$key])) {
                    self::block($key . ' invalide');
                }
            }
        }

        foreach ($data as $key => $value) {
            $data[$key] = self::sanitizeGenericValue($value, (string) $key);
        }

        return $data;
    }

    private static function sanitizeGenericValue($value, $key, $depth = 0)
    {
        if ($depth > self::MAX_CONFIG_DEPTH) {
            self::block('profondeur config excessive : ' . $key);
        }

        if (is_array($value)) {
            $clean = [];
            foreach ($value as $k => $v) {
                $clean[$k] = self::sanitizeGenericValue($v, $key, $depth + 1);
            }

            return $clean;
        }

        if (is_object($value)) {
            $encoded = json_encode($value);
            if ($encoded === false) {
                self::block('objet config invalide : ' . $key);
            }

            return self::sanitizeGenericValue(json_decode($encoded, true), $key, $depth + 1);
        }

        if (is_string($value)) {
            if (self::looksLikeSmartyDropper($value) || self::looksLikePhpWebshell($value) || self::hasTraversalOrWrapper($value)) {
                self::block('valeur config suspecte : ' . $key);
            }

            return $value;
        }

        return $value;
    }

    private static function assertSafeSmartyTemplate($content, $source)
    {
        if (self::looksLikeSmartyDropper($content) || self::looksLikePhpWebshell($content)) {
            self::throwBlock('template Smarty dangereux', $source);
        }
    }

    private static function scanOneFile($path, array &$findings)
    {
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        if (!in_array($ext, ['tpl', 'php', 'phtml', 'php5', 'php7'], true)) {
            return;
        }

        $content = @file_get_contents($path);
        if ($content === false) {
            return;
        }

        if ($ext === 'tpl') {
            self::scanSmartyContent($content, $path, $findings);
        } else {
            self::scanPhpContent($content, $path, $findings);
        }
    }

    private static function scanSmartyContent($content, $file, array &$findings)
    {
        $patterns = [
            'smarty_write_php' => '/file_put_contents\s*\([^)]*\.php/is',
            'smarty_php_tag' => '/<\?php/i',
            'smarty_superglobal' => '/\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b/i',
            'smarty_dangerous_function' => '/\b(?:eval|assert|system|exec|shell_exec|passthru|proc_open|popen|base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|fopen|fwrite|copy|rename|unlink|chmod|curl_exec)\s*\(/i',
            'smarty_dangerous_tag' => '/\{\s*(?:php|include_php|eval|insert)\b/i',
        ];
        self::scanWithPatterns($content, $file, $patterns, $findings, 'critical');
    }

    private static function scanPhpContent($content, $file, array &$findings)
    {
        $patterns = [
            'php_eval_base64_post' => '/eval\s*\(\s*base64_decode\s*\(\s*\$_(?:POST|REQUEST|GET)/i',
            'php_dynamic_execution' => '/\b(?:assert|system|exec|shell_exec|passthru|proc_open|popen)\s*\(\s*\$_(?:POST|REQUEST|GET|COOKIE)/i',
            'php_obfuscated_loader' => '/(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\([^;]{0,200}\$_(?:POST|REQUEST|GET|COOKIE)/is',
        ];
        self::scanWithPatterns($content, $file, $patterns, $findings, 'critical');
    }

    private static function scanWithPatterns($content, $file, array $patterns, array &$findings, $severity)
    {
        foreach ($patterns as $type => $pattern) {
            if (preg_match($pattern, $content, $m, PREG_OFFSET_CAPTURE)) {
                $line = substr_count(substr($content, 0, $m[0][1]), "\n") + 1;
                $findings[] = [
                    'severity' => $severity,
                    'type' => $type,
                    'file' => $file,
                    'line' => $line,
                    'match' => substr(preg_replace('/\s+/', ' ', $m[0][0]), 0, 160),
                ];
            }
        }
    }

    private static function getScanRoots()
    {
        // Perimetre volontairement strict : uniquement le module appagebuilder.
        // Ne jamais elargir ce scan a la racine PrestaShop, aux themes ou aux autres modules.
        $moduleRoot = _PS_MODULE_DIR_ . 'appagebuilder/';
        $real = realpath($moduleRoot);

        if ($real === false || !is_dir($real)) {
            return [];
        }

        return [$real];
    }

    private static function looksLikeSmartyDropper($value)
    {
        $value = (string) $value;
        $patterns = [
            '/\{\s*(?:php|include_php|eval|insert)\b/i',
            '/\{[^}]{0,400}\bfile_put_contents\s*\([^)]*\.php/is',
            '/\b(?:file_put_contents|fopen|fwrite|copy|rename|unlink|chmod|chown|mkdir|rmdir|touch|symlink)\s*\(/i',
            '/\b(?:file_get_contents|curl_exec)\s*\(/i',
            '/\b(?:base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|pack)\s*\(/i',
            '/\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/i',
            '/<\?php/i',
        ];
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }

        return false;
    }

    private static function looksLikePhpWebshell($value)
    {
        $value = (string) $value;
        $patterns = [
            '/eval\s*\(\s*base64_decode\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)/i',
            '/\b(?:assert|system|exec|shell_exec|passthru|proc_open|popen)\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)/i',
            '/\b(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\([^;]{0,200}\$_(?:POST|GET|REQUEST|COOKIE)/is',
        ];
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }

        return false;
    }

    private static function hasTraversalOrWrapper($value)
    {
        $value = str_replace('\\', '/', (string) $value);
        if (strpos($value, "\0") !== false) {
            return true;
        }
        if (preg_match('#(^|/)\.\.(/|$)#', $value) || strpos($value, '../') !== false || strpos($value, '..%2f') !== false || strpos($value, '%2e%2e') !== false) {
            return true;
        }
        if (preg_match('#\b(?:php|file|phar|zip|data|expect|glob|ssh2|rar|ogg|zlib)://#i', $value)) {
            return true;
        }
        if (preg_match('#^[a-z]:/#i', $value)) {
            return true;
        }

        return false;
    }

    private static function isSafeProductTemplatePath($path)
    {
        $path = str_replace('\\', '/', (string) $path);
        if ($path === 'catalog/_partials/miniatures/product.tpl') {
            return true;
        }
        if ($path === '' || self::hasTraversalOrWrapper($path) || strtolower(pathinfo($path, PATHINFO_EXTENSION)) !== 'tpl') {
            return false;
        }

        $real = realpath($path);
        if ($real === false || !is_file($real)) {
            return false;
        }

        $allowedRoots = [
            _PS_THEME_DIR_ . 'modules/appagebuilder/views/templates/front/profiles/',
            _PS_THEME_DIR_ . 'modules/appagebuilder/views/templates/front/products/',
            _PS_THEME_DIR_ . 'profiles/',
            _PS_MODULE_DIR_ . 'appagebuilder/views/templates/front/product-item/',
        ];

        $real = str_replace('\\', '/', $real);
        foreach ($allowedRoots as $root) {
            $rootReal = realpath($root);
            if ($rootReal && strpos($real, rtrim(str_replace('\\', '/', $rootReal), '/') . '/') === 0) {
                return true;
            }
        }

        return false;
    }

    private static function decodeBase64Loose($value)
    {
        $value = (string) $value;
        $clean = preg_replace('/[^A-Za-z0-9+\/=]/', '', $value);
        if ($clean !== $value) {
            self::logEvent('base64_obfuscation', 'Caracteres non base64 retires dans config apajax');
        }

        return base64_decode($clean, true);
    }

    private static function sanitizeIntList($value, $key = 'liste')
    {
        if (is_array($value)) {
            $parts = $value;
        } else {
            $raw = trim((string) $value);
            if ($raw !== '' && !preg_match('/^[0-9,\\s]+$/', $raw)) {
                self::block('liste numerique invalide : ' . $key);
            }
            $parts = explode(',', $raw);
        }

        $clean = [];
        foreach ($parts as $part) {
            $part = trim((string) $part);
            if ($part === '') {
                continue;
            }
            if (!preg_match('/^\\d+$/', $part)) {
                self::block('liste numerique invalide : ' . $key);
            }
            $clean[] = (string) (int) $part;
        }

        return implode(',', array_unique($clean));
    }

    private static function getRequestValue($key)
    {
        if (class_exists('Tools')) {
            $value = Tools::getValue($key, null);
            if ($value !== null) {
                return $value;
            }
        }
        if (isset($_POST[$key])) {
            return $_POST[$key];
        }
        if (isset($_GET[$key])) {
            return $_GET[$key];
        }

        return null;
    }

    private static function setRequestValue($key, $value)
    {
        if (isset($_POST[$key])) {
            $_POST[$key] = $value;
        }
        if (isset($_GET[$key])) {
            $_GET[$key] = $value;
        }
        $_REQUEST[$key] = $value;
    }

    private static function flattenValue($value, $maxLength = self::MAX_INSPECTION_VALUE, $depth = 0)
    {
        if ($depth > 12 || $maxLength <= 0) {
            return '';
        }

        if (is_array($value)) {
            $parts = [];
            $remaining = $maxLength;
            foreach ($value as $item) {
                if ($remaining <= 0) {
                    break;
                }
                $part = self::flattenValue($item, $remaining, $depth + 1);
                $parts[] = $part;
                $remaining -= strlen($part) + 1;
            }

            return substr(implode(' ', $parts), 0, $maxLength);
        }

        if (is_object($value)) {
            $encoded = json_encode($value);

            return $encoded === false ? '' : substr($encoded, 0, $maxLength);
        }

        return substr((string) $value, 0, $maxLength);
    }

    private static function throwBlock($reason, $detail)
    {
        self::logEvent('blocked_write', $reason . ' : ' . $detail);

        throw new Exception('Phenix AP PageBuilder Guard : ' . $reason);
    }

    private static function block($reason)
    {
        self::logEvent('blocked_request', $reason);
        if (!headers_sent()) {
            header('HTTP/1.1 403 Forbidden');
            header('Content-Type: application/json; charset=utf-8');
        }
        exit(json_encode([
            'hasError' => 1,
            'errors' => ['Requete bloquee par Phenix AP PageBuilder Guard.'],
        ]));
    }
}
