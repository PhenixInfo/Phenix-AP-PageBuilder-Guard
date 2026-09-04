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
    public const LOG_FILE = 'security.log.php';
    public const LOG_PREFIX = 'security.log';
    public const LEGACY_LOG_FILE = 'security.log';
    public const LOG_GUARD = "<?php exit; ?>\n";
    public const MAX_LOG_BYTES = 2097152;
    public const MAX_LOG_FILES = 3;
    public const MAX_LOG_VALUE = 1024;
    public const MAX_LOG_PAYLOAD = 4096;
    public const MAX_INSPECTION_VALUE = 4096;
    public const MAX_INSPECTION_TOTAL = 16384;
    public const MAX_CONFIG_DEPTH = 32;

    public static function guardApAjax($tokenRequired = false)
    {
        if (!self::isEnabled()) {
            return;
        }

        self::guardCommonRequestPayload();

        // Les controles sont volontairement cumulatifs. Un attaquant ne doit pas
        // pouvoir ajouter leoajax=1 pour court-circuiter une verification galerie
        // ou config presente dans la meme requete.
        if (self::getRequestValue('leoajax') == 1) {
            if ($tokenRequired && (!class_exists('Tools') || Tools::getToken(false) !== (string) self::getRequestValue('token'))) {
                self::block('token AJAX invalide');
            }
            self::sanitizeAjaxIntegerParameters();
            self::sanitizeAjaxSortParameters();
            self::guardUnknownAjaxSqlInjection();
            self::guardShortcodeAjax();
        }

        if (strcasecmp((string) self::getRequestValue('widget'), 'ApImageGallery') === 0) {
            self::guardImageGalleryAjax();
        }

        if (self::getRequestValue('config') !== null && self::getRequestValue('config') !== '') {
            self::sanitizeConfigRequest();
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
        if (is_link($target)) {
            self::throwBlock('cible ecriture symbolique interdite', $target);
        }

        $dir = dirname($target);
        $realDir = realpath($dir);
        if ($realDir === false) {
            self::throwBlock('repertoire ecriture introuvable', $target);
        }

        $root = realpath(_PS_ROOT_DIR_);
        if ($root !== false) {
            $rootNormalized = rtrim(str_replace('\\', '/', $root), '/') . '/';
            $realDirNormalized = rtrim(str_replace('\\', '/', $realDir), '/') . '/';
            if (strpos($realDirNormalized, $rootNormalized) !== 0) {
                self::throwBlock('ecriture hors racine PrestaShop', $target);
            }
        }

        $allowedWriteRoots = [
            realpath(_PS_MODULE_DIR_ . 'appagebuilder/'),
            defined('_PS_THEME_DIR_') ? realpath(_PS_THEME_DIR_) : false,
        ];
        $insideAllowedRoot = false;
        foreach ($allowedWriteRoots as $allowedWriteRoot) {
            if ($allowedWriteRoot === false) {
                continue;
            }
            $allowedWriteRoot = rtrim(str_replace('\\', '/', $allowedWriteRoot), '/') . '/';
            $realDirNormalized = rtrim(str_replace('\\', '/', $realDir), '/') . '/';
            if (strpos($realDirNormalized, $allowedWriteRoot) === 0) {
                $insideAllowedRoot = true;

                break;
            }
        }
        if (!$insideAllowedRoot) {
            self::throwBlock('ecriture hors perimetre AP Page Builder/theme', $target);
        }

        $base = strtolower(basename($target));
        if (in_array($base, ['.htaccess', '.user.ini', 'php.ini', 'web.config'], true)) {
            self::throwBlock('fichier de configuration executable interdit', $target);
        }

        // ApPageSetting::writeFile() est utilise par les branches 2.x pour les
        // templates, CSS, JS et exports XML. Toute autre extension est refusee
        // afin qu'un chemin controle ne puisse jamais deposer un script PHP.
        $extension = strtolower(pathinfo($target, PATHINFO_EXTENSION));
        if (!in_array($extension, ['tpl', 'js', 'css', 'xml'], true)) {
            self::throwBlock('extension ecriture non autorisee', $target);
        }

        $content = (string) $value;
        if (preg_match('/<\?(?:php|=)/i', $content) || self::looksLikePhpWebshell($content)) {
            self::throwBlock('contenu executable interdit', $target);
        }

        if ($extension === 'tpl') {
            $base = basename($target);
            if (!preg_match('/^[a-zA-Z0-9_.-]+\.tpl$/', $base)) {
                self::throwBlock('nom de template non autorise', $target);
            }
            self::assertSafeSmartyTemplate($content, $target);
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
        $default = 'catalog/_partials/miniatures/product.tpl';
        if (!self::isEnabled()) {
            $cookieName = 'productItemPathApProductList_' . $formId;

            return isset(Context::getContext()->cookie->{$cookieName}) ? Context::getContext()->cookie->{$cookieName} : $default;
        }

        $formId = (string) $formId;
        if ($formId === '') {
            self::logEvent('product_form_id_missing', 'form_id absent : template produit par defaut utilise');

            return $default;
        }
        if (!preg_match('/^[a-zA-Z0-9_-]{1,80}$/', $formId)) {
            self::logEvent('product_form_id_rejected', 'form_id invalide : template produit par defaut utilise');

            return $default;
        }

        $cookieName = 'productItemPathApProductList_' . $formId;
        $path = null;
        if (isset(Context::getContext()->cookie->{$cookieName})) {
            // Seule la Cookie PrestaShop signee/chiffree est une source de confiance.
            // Ne jamais retomber sur $_COOKIE brut, forgeable par le client.
            $path = Context::getContext()->cookie->{$cookieName};
        }

        if (is_string($path)) {
            $resolved = self::resolveSafeProductTemplatePath($path);
            if ($resolved !== false) {
                return $resolved;
            }
        }

        if (is_string($path) && $path !== '') {
            self::logEvent('product_item_path_rejected', 'Chemin refuse : ' . $path);
        }

        return $default;
    }

    public static function scanInstallation()
    {
        $findings = [];
        $root = realpath(_PS_MODULE_DIR_ . 'appagebuilder/');
        if ($root === false || !is_dir($root)) {
            return $findings;
        }
        $rootNormalized = rtrim(str_replace('\\', '/', $root), '/') . '/';

        // Perimetre volontairement strict : uniquement /modules/appagebuilder/.
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
        );
        foreach ($iterator as $fileInfo) {
            if (!$fileInfo->isFile() || $fileInfo->isLink()) {
                continue;
            }

            $realFile = realpath($fileInfo->getPathname());
            if ($realFile === false || strpos(str_replace('\\', '/', $realFile), $rootNormalized) !== 0) {
                continue;
            }

            self::scanOneFile($realFile, $findings);
        }

        return $findings;
    }

    public static function logEvent($type, $message)
    {
        $dir = self::getLogDir();
        if (!self::ensurePrivateDirectory($dir)) {
            return false;
        }

        $log = self::getProtectedLogPath($dir, 0);
        self::rotateLogs($dir);

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

        if (!is_file($log)) {
            @file_put_contents($log, self::LOG_GUARD, LOCK_EX);
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
        $files = [];
        for ($i = 0; $i <= self::MAX_LOG_FILES; ++$i) {
            $files[] = self::getProtectedLogPath($dir, $i);
            $files[] = self::getLegacyLogPath($dir, $i);
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
            foreach ([self::getProtectedLogPath($dir, $i), self::getLegacyLogPath($dir, $i)] as $file) {
                if (is_file($file) && @unlink($file)) {
                    ++$removed;
                }
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
            foreach ([self::getProtectedLogPath($dir, $i), self::getLegacyLogPath($dir, $i)] as $file) {
                if (is_file($file)) {
                    ++$files;
                    $size = @filesize($file);
                    if ($size !== false) {
                        $bytes += (int) $size;
                    }
                }
            }
        }

        return ['path' => self::getProtectedLogPath($dir, 0), 'bytes' => $bytes, 'files' => $files];
    }

    private static function getProtectedLogPath($dir, $index)
    {
        $index = (int) $index;
        if ($index <= 0) {
            return $dir . '/' . self::LOG_FILE;
        }

        return $dir . '/' . self::LOG_PREFIX . '.' . $index . '.php';
    }

    private static function getLegacyLogPath($dir, $index)
    {
        $index = (int) $index;

        return $dir . '/' . self::LEGACY_LOG_FILE . ($index > 0 ? '.' . $index : '');
    }

    private static function getLogDir()
    {
        return rtrim(_PS_ROOT_DIR_, '/\\') . '/var/phappagebuilderguard/logs';
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

    private static function rotateLogs($dir)
    {
        $log = self::getProtectedLogPath($dir, 0);
        if (!is_file($log)) {
            return;
        }
        $size = @filesize($log);
        if ($size === false || $size < self::MAX_LOG_BYTES) {
            return;
        }

        $last = self::getProtectedLogPath($dir, self::MAX_LOG_FILES);
        if (is_file($last)) {
            @unlink($last);
        }
        for ($i = self::MAX_LOG_FILES - 1; $i >= 1; --$i) {
            $src = self::getProtectedLogPath($dir, $i);
            $dst = self::getProtectedLogPath($dir, $i + 1);
            if (is_file($src)) {
                @rename($src, $dst);
            }
        }
        @rename($log, self::getProtectedLogPath($dir, 1));
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
        $query = self::filterSecurityPayload($query);
        $query = self::sanitizeLogValue($query, 0);
        $qs = http_build_query($query, '', '&');

        return self::cleanLogString($path . ($qs !== '' ? '?' . $qs : ''), 2048);
    }

    private static function getSafePayload()
    {
        $payload = [];
        if (!empty($_GET)) {
            $get = self::filterSecurityPayload($_GET);
            if ($get) {
                $payload['get'] = self::sanitizeLogValue($get, 0);
            }
        }
        if (!empty($_POST)) {
            $post = self::filterSecurityPayload($_POST);
            if ($post) {
                $payload['post'] = self::sanitizeLogValue($post, 0);
            }
        }

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json !== false && strlen($json) > self::MAX_LOG_PAYLOAD) {
            return ['_truncated' => substr($json, 0, self::MAX_LOG_PAYLOAD) . '...'];
        }
        return $payload;
    }

    private static function filterSecurityPayload(array $bucket)
    {
        $clean = [];
        foreach ($bucket as $key => $value) {
            $key = (string) $key;
            if (!preg_match('/^(?:action|leoajax|token|widget|show_number|assign|config|p|page|cat_list|list_cat|image_product|wishlist_compare|tabshortcode|tabshortcodekey|form_id|order_by|order_way|categorybox|manufacture|supplier|manuselect|profile|override_folder|nb_products|page_number|columns|limit|use_showmore|product_[a-z0-9_]+|leo_[a-z0-9_]+|pro_[a-z0-9_]+|value_by_[a-z0-9_]+)$/i', $key)) {
                continue;
            }
            $clean[$key] = $value;
        }

        return $clean;
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
            'list_cat',
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
            'categorybox',
            'manufacture',
            'supplier',
            'product_id',
            'manuselect',
        ];

        foreach ($intListKeys as $key) {
            $value = self::getRequestValue($key);
            if ($value === null || $value === '') {
                continue;
            }
            self::setRequestValue($key, self::sanitizeIntList($value, $key));
        }
    }

    private static function sanitizeAjaxSortParameters()
    {
        $orderBy = self::getRequestValue('order_by');
        if ($orderBy !== null && $orderBy !== '') {
            $allowed = ['position', 'name', 'price', 'id_product', 'date_add', 'date_upd', 'reference', 'manufacturer', 'quantity'];
            if (!in_array((string) $orderBy, $allowed, true)) {
                self::block('order_by AJAX invalide');
            }
        }

        $orderWay = self::getRequestValue('order_way');
        if ($orderWay !== null && $orderWay !== '') {
            $orderWay = strtolower((string) $orderWay);
            if (!in_array($orderWay, ['asc', 'desc', 'random'], true)) {
                self::block('order_way AJAX invalide');
            }
        }
    }

    private static function guardUnknownAjaxSqlInjection()
    {
        $skip = ['config', 'assign', 'tabshortcode', 'tabshortcodekey'];
        foreach ([$_GET, $_POST] as $bucket) {
            foreach ($bucket as $key => $value) {
                if (in_array((string) $key, $skip, true) || is_array($value) || is_object($value)) {
                    continue;
                }
                // GET/POST sont deja URL-decodes par PHP. Scanner la valeur complete
                // evite qu'un long prefixe neutre masque une SQLi placee plus loin.
                if (self::looksLikeHighConfidenceSqlInjection((string) $value)) {
                    self::block('motif SQLi AJAX detecte : ' . substr((string) $key, 0, 80));
                }
            }
        }
    }

    private static function looksLikeHighConfidenceSqlInjection($value)
    {
        $value = (string) $value;

        // MySQL accepte les commentaires entre les mots-cles. Les normaliser ici
        // evite qu un parametre AJAX inconnu contourne le filet generique avec
        // des formes telles que OR/**/1=1 ou UNION/**/SELECT.
        $value = preg_replace_callback('/\/\*!\s*\d{0,6}\s*(.*?)\*\//s', function ($match) {
            return ' ' . $match[1] . ' ';
        }, $value);
        $value = preg_replace('/\/\*.*?\*\//s', ' ', $value);

        // Ce filet ne doit bloquer que des structures SQL fortement caracterisees.
        // Les mots anglais courants (Select from, Insert into, Sleep (...)) ne sont
        // pas suffisants a eux seuls : les parametres historiques connus sont deja
        // valides strictement plus haut.
        $patterns = [
            '/\bunion\s+(?:all\s+)?select\b/i',
            '/\binformation_schema\b/i',
            '/\bload_file\s*\(/i',
            '/\binto\s+(?:out|dump)file\b/i',
            '/;\s*(?:select|insert|update|delete)\b/i',
            '/(?:[\)\'"]|\bselect\b)\s*(?:or|and)?\s*.{0,80}\b(?:sleep|benchmark)\s*\(/is',
            '/[\)\'"]\s*\b(?:or|and)\b\s*(?:\(?\s*)?(?:\d+\s*=\s*\d+|(?:ord|mid|substring|length)\s*\()/i',
            '/[\)\'"]\s*\b(?:or|and)\b\s*\(?\s*select\b.{0,160}\bfrom\b/is',
        ];
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }

        return false;
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
        if (is_array($rawShowNumber) || is_object($rawShowNumber)) {
            self::block('show_number galerie invalide');
        }
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
                self::logEvent('config_form_id_rejected', 'form_id invalide ignore dans config produit');
                unset($data['form_id']);
            }
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
            'smarty_write_php' => '/file_put_contents\s*\([^)]*\.(?:php|phtml|php[0-9])\b/is',
            'smarty_php_tag' => '/<\?php/i',
            'smarty_superglobal' => '/\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b/i',
            'smarty_execution_expression' => '/\{[^}]{0,600}\b(?:eval|assert|system|exec|shell_exec|passthru|proc_open|popen|file_put_contents|fopen|fwrite|unlink|chmod|chown|mkdir|rmdir|symlink|base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin)\s*\(/is',
            'smarty_dangerous_tag' => '/\{\s*(?:php|include_php|eval)\b/i',
        ];
        self::scanWithPatterns($content, $file, $patterns, $findings);
    }

    private static function scanPhpContent($content, $file, array &$findings)
    {
        $patterns = [
            'php_eval_base64_post' => '/eval\s*\(\s*base64_decode\s*\(\s*\$_(?:POST|REQUEST|GET)/i',
            'php_dynamic_execution' => '/\b(?:assert|system|exec|shell_exec|passthru|proc_open|popen)\s*\(\s*\$_(?:POST|REQUEST|GET|COOKIE)/i',
            'php_obfuscated_loader' => '/(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\([^;]{0,200}\$_(?:POST|REQUEST|GET|COOKIE)/is',
        ];
        self::scanWithPatterns($content, $file, $patterns, $findings);
    }

    private static function scanWithPatterns($content, $file, array $patterns, array &$findings)
    {
        foreach ($patterns as $type => $pattern) {
            if (preg_match($pattern, $content, $m, PREG_OFFSET_CAPTURE)) {
                $line = substr_count(substr($content, 0, $m[0][1]), "\n") + 1;
                $findings[] = [
                    'type' => $type,
                    'file' => $file,
                    'line' => $line,
                    'match' => substr(preg_replace('/\s+/', ' ', $m[0][0]), 0, 160),
                ];
            }
        }
    }

    private static function looksLikeSmartyDropper($value)
    {
        $value = (string) $value;
        $patterns = [
            '/\{\s*(?:php|include_php|eval)\b/i',
            '/\{[^}]{0,600}\b(?:file_put_contents|fopen|fwrite|unlink|chmod|chown|mkdir|rmdir|symlink|assert|system|exec|shell_exec|passthru|proc_open|popen|base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin)\s*\(/is',
            '/\bfile_put_contents\s*\([^)]*\.(?:php|phtml|php[0-9])\b/is',
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

    private static function resolveSafeProductTemplatePath($path)
    {
        $path = str_replace('\\', '/', trim((string) $path));
        if ($path === 'catalog/_partials/miniatures/product.tpl') {
            return $path;
        }
        if ($path === '' || self::hasTraversalOrWrapper($path) || strtolower(pathinfo($path, PATHINFO_EXTENSION)) !== 'tpl') {
            return false;
        }

        $allowedRoots = [
            _PS_THEME_DIR_ . 'modules/appagebuilder/views/templates/front/profiles/',
            _PS_THEME_DIR_ . 'modules/appagebuilder/views/templates/front/products/',
            _PS_THEME_DIR_ . 'profiles/',
            _PS_MODULE_DIR_ . 'appagebuilder/views/templates/front/product-item/',
        ];

        $candidates = [];
        if (preg_match('#^(?:/|[a-z]:/)#i', $path)) {
            $candidates[] = $path;
        } else {
            $candidates[] = rtrim(_PS_ROOT_DIR_, '/\\') . '/' . ltrim($path, '/');
            $candidates[] = rtrim(_PS_THEME_DIR_, '/\\') . '/' . ltrim($path, '/');
            $candidates[] = rtrim(_PS_MODULE_DIR_, '/\\') . '/appagebuilder/' . ltrim($path, '/');
        }

        foreach ($candidates as $candidate) {
            $real = realpath($candidate);
            if ($real === false || !is_file($real)) {
                continue;
            }
            $real = str_replace('\\', '/', $real);
            foreach ($allowedRoots as $root) {
                $rootReal = realpath($root);
                if ($rootReal === false) {
                    continue;
                }
                $rootReal = rtrim(str_replace('\\', '/', $rootReal), '/') . '/';
                if (strpos($real, $rootReal) === 0) {
                    // Retourne le chemin canonique valide. Smarty inclura ainsi
                    // exactement le fichier qui vient d'etre valide.
                    return $real;
                }
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
            'success' => false,
            'hasError' => 1,
            'error' => true,
            'status' => 'blocked',
            'message' => 'Requete bloquee par Phenix AP PageBuilder Guard.',
            'errors' => ['Requete bloquee par Phenix AP PageBuilder Guard.'],
        ]));
    }
}
