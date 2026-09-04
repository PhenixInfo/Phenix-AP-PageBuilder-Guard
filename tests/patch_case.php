<?php
/**
 * Development-only patch/rollback harness.
 */
$psRoot = $argv[1];
$moduleSource = $argv[2];
define('_PS_VERSION_', '1.7.8.11');
define('_PS_ROOT_DIR_', $psRoot);
define('_PS_MODULE_DIR_', rtrim($psRoot, '/\\') . '/modules/');
define('_PS_THEME_DIR_', rtrim($psRoot, '/\\') . '/themes/classic/');
class Configuration { private static $data = []; public static function get($k) { return isset(self::$data[$k]) ? self::$data[$k] : null; } public static function updateValue($k,$v) { self::$data[$k]=$v; return true; } }
class CookieStub { public function __get($k) { return null; } public function __isset($k) { return false; } }
class Context { public $cookie; private static $i; public function __construct(){$this->cookie=new CookieStub();} public static function getContext(){if(!self::$i)self::$i=new self();return self::$i;} }
class Tools { public static function getValue($k,$d=null){return $d;} public static function getToken($x=false){return 'token';} }
class Module { public $version=''; public static function getInstanceByName($n){$m=new self(); $f=_PS_MODULE_DIR_.'appagebuilder/appagebuilder.php'; if(is_file($f) && preg_match("/\\$this->version\\s*=\\s*['\"]([^'\"]+)/", file_get_contents($f), $x)) $m->version=$x[1]; return $m; } }
require $moduleSource . '/classes/PhApPageBuilderGuard.php';
class Harness extends PhApPageBuilderGuardCore {
    public function doPatch(){ return $this->applyPatch(); }
    public function doRollback(){ return $this->rollbackPatch(); }
    public function doBackup($label='matrix'){ return $this->createManualBackup($label); }
    public function doRestore($snapshot){ return $this->restoreManualBackup($snapshot); }
    public function status(){ return $this->getPatchStatus(); }
    public function detected(){ return $this->detectInstalledApPageBuilderVersion(); }
}
$h = new Harness();
$targets = [
    'apajax.php',
    'classes/ApPageSetting.php',
    'classes/shortcodes/ApProductList.php',
    'classes/shortcodes/ApGenCode.php',
    'controllers/admin/AdminApPageBuilderThemeConfiguration.php',
];
function hashes($root,$targets){$a=[];foreach($targets as $t){$p=$root.'/modules/appagebuilder/'.$t;$a[$t]=is_file($p)?hash_file('sha256',$p):null;}return $a;}
$before=hashes($psRoot,$targets);
$ver=$h->detected();
$r1=$h->doPatch();
$after1=hashes($psRoot,$targets);
$r2=$h->doPatch();
$after2=hashes($psRoot,$targets);
$phpLint=[];
foreach($targets as $t){$p=$psRoot.'/modules/appagebuilder/'.$t;if(substr($p,-4)==='.php' && is_file($p)){exec('php -l '.escapeshellarg($p).' 2>&1',$o,$rc);$phpLint[$t]=['rc'=>$rc,'out'=>implode("\n",$o)];}}
$rb=$h->doRollback();
$afterRollback=hashes($psRoot,$targets);

// Manual snapshot is an independent safety path. Verify exact restoration too.
$manual=$h->doBackup('matrix-manual');
$manualSnapshot=isset($manual['snapshot'])?$manual['snapshot']:(isset($manual['name'])?$manual['name']:null);
$mutatedTarget=null;
$manualRestore=null;
$afterManualRestore=null;
if($manualSnapshot){
    foreach($targets as $t){
        $candidate=$psRoot.'/modules/appagebuilder/'.$t;
        if(is_file($candidate)){$mutatedTarget=$candidate;break;}
    }
    if($mutatedTarget){file_put_contents($mutatedTarget,"\n/* matrix mutation */\n",FILE_APPEND);}
    $manualRestore=$h->doRestore($manualSnapshot);
    $afterManualRestore=hashes($psRoot,$targets);
}
echo json_encode(['version'=>$ver,'patch1'=>$r1,'patch2'=>$r2,'rollback'=>$rb,'before'=>$before,'after1'=>$after1,'after2'=>$after2,'afterRollback'=>$afterRollback,'lint'=>$phpLint,'status'=>$h->status(),'manual'=>$manual,'manualSnapshot'=>$manualSnapshot,'manualRestore'=>$manualRestore,'afterManualRestore'=>$afterManualRestore],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);
