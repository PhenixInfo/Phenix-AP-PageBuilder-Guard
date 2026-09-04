<?php
/**
 * Local runtime harness for Phenix AP PageBuilder Guard.
 * Dev-only: never package in the Marketplace ZIP.
 */
$mode = isset($argv[1]) ? $argv[1] : '';
$payload = isset($argv[2]) ? json_decode(base64_decode($argv[2]), true) : [];
$root = isset($payload['root']) ? $payload['root'] : sys_get_temp_dir() . '/phapb-fuzz-root';
@mkdir($root . '/modules/appagebuilder/views/templates/front/product-item', 0777, true);
@mkdir($root . '/themes/test/modules/appagebuilder/views/templates/front/profiles', 0777, true);
define('_PS_VERSION_', '1.7.8.11');
define('_PS_ROOT_DIR_', $root);
define('_PS_MODULE_DIR_', $root . '/modules/');
define('_PS_THEME_DIR_', $root . '/themes/test/');
class Configuration { public static function get($key) { return true; } }
class CookieStub { private $data = []; public function __set($key, $value) { $this->data[$key] = $value; } public function __get($key) { return isset($this->data[$key]) ? $this->data[$key] : null; } public function __isset($key) { return isset($this->data[$key]); } }
class Context {
    public $cookie;
    private static $instance;
    public function __construct() { $this->cookie = new CookieStub(); }
    public static function getContext() { if (!self::$instance) { self::$instance = new self(); } return self::$instance; }
}
class Tools {
    public static function getValue($key, $default = null) { if (isset($_POST[$key])) { return $_POST[$key]; } if (isset($_GET[$key])) { return $_GET[$key]; } return $default; }
    public static function getToken($unused = false) { return 'good'; }
}
require dirname(__DIR__) . '/module/classes/PhApPageBuilderGuard.php';
$_GET = isset($payload['get']) && is_array($payload['get']) ? $payload['get'] : [];
$_POST = isset($payload['post']) && is_array($payload['post']) ? $payload['post'] : [];
if (isset($payload['generated_unknown_len'])) {
    $length = max(0, min((int) $payload['generated_unknown_len'], 8 * 1024 * 1024));
    $_GET = ['leoajax' => 1, 'future_large' => str_repeat('A', $length)];
}
$_COOKIE = isset($payload['cookie']) && is_array($payload['cookie']) ? $payload['cookie'] : [];
$_REQUEST = array_merge($_GET, $_POST);
if (isset($payload['context_cookie']) && is_array($payload['context_cookie'])) {
    foreach ($payload['context_cookie'] as $key => $value) {
        Context::getContext()->cookie->{$key} = $value;
    }
}
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI'] = '/modules/appagebuilder/apajax.php';

try {
    if ($mode === 'ajax') {
        PhApPageBuilderGuardCore::guardApAjax(false);
        echo "ALLOWED\n";
    } elseif ($mode === 'write') {
        PhApPageBuilderGuardCore::guardWriteFile($payload['target'], isset($payload['content']) ? $payload['content'] : '');
        echo "ALLOWED\n";
    } elseif ($mode === 'scan') {
        echo json_encode(PhApPageBuilderGuardCore::scanInstallation(), JSON_UNESCAPED_SLASHES) . "\n";
    } elseif ($mode === 'path') {
        echo PhApPageBuilderGuardCore::getSafeProductItemPath(isset($payload['form_id']) ? $payload['form_id'] : '') . "\n";
    } elseif ($mode === 'log') {
        PhApPageBuilderGuardCore::logEvent('fuzz_test', 'local regression');
        $log = $root . '/var/phappagebuilderguard/logs/security.log.php';
        echo is_file($log) ? file_get_contents($log) : "NO_LOG\n";
    } else {
        fwrite(STDERR, "Unknown mode\n");
        exit(2);
    }
} catch (Exception $e) {
    echo "BLOCKED:" . $e->getMessage() . "\n";
}
