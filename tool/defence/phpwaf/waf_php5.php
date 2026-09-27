<?php
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);
$get = $_GET;
$post = $_POST;
$file = $_FILES;
$cookie = $_COOKIE;
$request = $_REQUEST;

function wafGetBlacklist()
{
    static $blacklist = null;
    if ($blacklist !== null) {
        return $blacklist;
    }

    $words = <<<'WAFWORDS'
system
exec
passthru
shell_exec
proc_open
popen
eval
assert
include
require
include_once
require_once
file_get_contents
file_put_contents
fopen
fwrite
unlink
mkdir
rmdir
scandir
glob
unserialize
phpinfo
ini_set
base64_decode
urldecode
curl_exec
fsockopen
stream_socket_client
socket_connect
php://
file://
data://
phar://
zip://
http://
https://
ftp://
sh
bash
cmd
powershell
whoami
id
uname
ifconfig
ipconfig
netstat
tasklist
dir
ls
cat
awk
sed
cut
sort
find
locate
rm
del
wget
curl
nc
netcat
telnet
ping
scp
ssh
python
python3
perl
php
ruby
lua
node
java
flag
/flag
/etc/passwd
/etc/shadow
win.ini
hosts
.ssh
authorized_keys
id_rsa
&&
||
|
`
$(
${
>>
>
<<
<
#
/*
*/
WAFWORDS;

    $rows = preg_split('/\r\n|\r|\n/', $words);
    $blacklist = array();
    foreach ($rows as $row) {
        $item = trim($row);
        if ($item === '') {
            continue;
        }
        $blacklist[$item] = true;
    }
    $blacklist = array_keys($blacklist);
    $blacklist = wafApplyStrictLevel($blacklist);

    usort($blacklist, function ($left, $right) {
        $leftLength = strlen($left);
        $rightLength = strlen($right);
        if ($leftLength === $rightLength) {
            return 0;
        }
        return ($leftLength < $rightLength) ? 1 : -1;
    });

    return $blacklist;
}

function wafGetMode()
{
    $mode = defined('PHPWAF_MODE') ? (int) PHPWAF_MODE : 1;
    return $mode === 2 ? 2 : 1;
}

function wafGetStrictLevel()
{
    $level = defined('PHPWAF_STRICT_LEVEL') ? (int) PHPWAF_STRICT_LEVEL : 3;
    if ($level < 1) {
        return 1;
    }
    if ($level > 3) {
        return 3;
    }
    return $level;
}

function wafGetRedirectPath()
{
    if (defined('PHPWAF_REDIRECT_PATH') && PHPWAF_REDIRECT_PATH !== '') {
        return (string) PHPWAF_REDIRECT_PATH;
    }
    $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
    $path = parse_url($uri, PHP_URL_PATH);
    return $path ? $path : '/';
}

function wafApplyStrictLevel($blacklist)
{
    $level = wafGetStrictLevel();
    if ($level >= 3) {
        return $blacklist;
    }

    $level1 = array('system', 'exec', 'passthru', 'shell_exec', 'eval', 'assert', 'base64_decode', 'php://', 'file://', 'data://', 'phar://', 'flag', '/flag', '&&', '||', '|', '`', '$(', '${');
    $level2 = array_merge($level1, array('preg_replace', 'call_user_func', 'include', 'require', 'file_get_contents', 'file_put_contents', 'curl_exec', 'fsockopen', 'stream_socket_client', 'socket_connect', 'wget', 'curl', 'nc', 'netcat', 'telnet', 'scp', 'ssh', 'python', 'python3', 'perl', 'php', 'node', 'java', '/etc/passwd', '/etc/shadow', '.ssh', 'authorized_keys', 'id_rsa', 'rm', 'del'));
    $allow = $level === 1 ? $level1 : $level2;
    $allowMap = array_fill_keys($allow, true);
    $filtered = array();
    foreach ($blacklist as $keyword) {
        if (isset($allowMap[$keyword])) {
            $filtered[] = $keyword;
        }
    }
    return $filtered;
}

function wafGetHeaderKeywords()
{
    return array('system', 'exec', 'passthru', 'shell_exec', 'eval', 'assert', 'base64_decode', 'phpinfo', 'flag', '/flag');
}

function wafSanitizeFlagContent($buffer)
{
    return preg_replace_callback('/(flag\{)[^}\r\n]*(\})/i', create_function('$matches', "return \$matches[1] . '383f0516865160a512df45a928969e12' . \$matches[2];"), $buffer);
}

function wafGetRawBody()
{
    static $rawBody = null;
    if ($rawBody === null) {
        $rawBody = file_get_contents('php://input');
        if ($rawBody === false) {
            $rawBody = '';
        }
    }
    return $rawBody;
}

function wafGetRandomSuffix()
{
    if (function_exists('random_bytes')) {
        return bin2hex(random_bytes(6));
    }
    return substr(md5(uniqid(mt_rand(), true)), 0, 12);
}

function wafReplaceKeywordsInString($value, $keywords, &$matchedKeywords)
{
    $changed = false;
    foreach ($keywords as $keyword) {
        $pattern = '/' . preg_quote($keyword, '/') . '/i';
        if (preg_match($pattern, $value) !== 1) {
            continue;
        }
        $value = preg_replace($pattern, '', $value);
        $matchedKeywords[$keyword] = true;
        $changed = true;
    }
    return array($value, $changed);
}

function wafShouldSkipFileKey($key)
{
    return in_array($key, array('tmp_name', 'error', 'size'), true);
}

function wafSanitizeValue(&$value, $keywords, &$matchedKeywords, &$matchedFields, $path, $isFilePayload)
{
    $changed = false;
    if (is_array($value)) {
        foreach ($value as $key => &$item) {
            if ($isFilePayload && wafShouldSkipFileKey($key)) {
                continue;
            }
            $childPath = $path === '' ? (string) $key : $path . '.' . $key;
            if (wafSanitizeValue($item, $keywords, $matchedKeywords, $matchedFields, $childPath, $isFilePayload)) {
                $changed = true;
            }
        }
        unset($item);
        return $changed;
    }

    if (!is_string($value) || $value === '') {
        return false;
    }
    $localMatches = array();
    list($sanitizedValue, $replaced) = wafReplaceKeywordsInString($value, $keywords, $localMatches);
    if (!$replaced) {
        return false;
    }
    $value = $sanitizedValue;
    $matchedFields[$path] = array_keys($localMatches);
    foreach ($localMatches as $keyword => $state) {
        $matchedKeywords[$keyword] = $state;
    }
    return true;
}

function getAllHeadersSafe()
{
    if (function_exists('getallheaders')) {
        return getallheaders();
    }
    $headers = array();
    foreach ($_SERVER as $key => $value) {
        if (strpos($key, 'HTTP_') === 0) {
            $name = str_replace('_', '-', substr($key, 5));
            $name = ucwords(strtolower($name), '-');
            $headers[$name] = $value;
        }
    }
    if (isset($_SERVER['CONTENT_TYPE'])) {
        $headers['Content-Type'] = $_SERVER['CONTENT_TYPE'];
    }
    if (isset($_SERVER['CONTENT_LENGTH'])) {
        $headers['Content-Length'] = $_SERVER['CONTENT_LENGTH'];
    }
    return $headers;
}

function wafBuildRawRequest($snapshot)
{
    $method = $snapshot['method'] !== '' ? $snapshot['method'] : 'GET';
    $uri = $snapshot['uri'] !== '' ? $snapshot['uri'] : '/';
    $protocol = $snapshot['protocol'] !== '' ? $snapshot['protocol'] : 'HTTP/1.1';
    $headers = $snapshot['headers'];
    $rawBody = $snapshot['raw_body'];

    if (!isset($headers['Cookie']) && !empty($snapshot['cookie'])) {
        $cookiePairs = array();
        foreach ($snapshot['cookie'] as $key => $value) {
            $cookiePairs[] = $key . '=' . $value;
        }
        $headers['Cookie'] = implode('; ', $cookiePairs);
    }
    if ($rawBody !== '' && !isset($headers['Content-Length'])) {
        $headers['Content-Length'] = strlen($rawBody);
    }

    $lines = array($method . ' ' . $uri . ' ' . $protocol);
    foreach ($headers as $key => $value) {
        $lines[] = $key . ': ' . $value;
    }
    return implode("\r\n", $lines) . "\r\n\r\n" . $rawBody;
}

function wafGetStorageDir()
{
    if (defined('PHPWAF_LOG_DIR')) {
        return rtrim(PHPWAF_LOG_DIR, '\\/');
    }
    return '/tmp/.phpwaf_logs';
}

function wafLogAll()
{
    // 默认只记录被拦截的请求；置 PHPWAF_LOG_ALL=1 后记录全部请求
    // （用于 AWD 中观察对手完整流量，注意请求量大时会持续落盘）
    if (defined('PHPWAF_LOG_ALL')) {
        return (int) PHPWAF_LOG_ALL === 1;
    }

    return false;
}

function saveRequest($rawRequest)
{
    $storageDir = wafGetStorageDir();
    if (!is_dir($storageDir) || !is_writable($storageDir)) {
        error_log('PHPWAF log dir not writable: ' . $storageDir);
        return false;
    }
    // 全量记录模式下设上限，避免正常流量刷爆磁盘
    if (wafLogAll()) {
        $existing = @glob($storageDir . DIRECTORY_SEPARATOR . '*.http');
        if (is_array($existing) && count($existing) >= 2000) {
            return false;
        }
    }
    $file = $storageDir . DIRECTORY_SEPARATOR . date('Ymd_His') . '_' . wafGetRandomSuffix() . '.http';
    return file_put_contents($file, $rawRequest) !== false ? $file : false;
}

function wafSanitizeResponse($buffer)
{
    return wafSanitizeFlagContent($buffer);
}

$blacklist = wafGetBlacklist();
$originalSnapshot = array(
    'time' => date('Y-m-d H:i:s'),
    'method' => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '',
    'uri' => isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '',
    'query_string' => isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '',
    'protocol' => isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : '',
    'remote_addr' => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '',
    'headers' => getAllHeadersSafe(),
    'raw_body' => wafGetRawBody(),
    'get' => $_GET,
    'post' => $_POST,
    'cookie' => $_COOKIE,
    'files' => $_FILES,
);
$originalSnapshot['raw_request'] = wafBuildRawRequest($originalSnapshot);

$matchedKeywords = array();
$matchedFields = array();
$suspicious = false;

if (wafSanitizeValue($_GET, $blacklist, $matchedKeywords, $matchedFields, 'get', false)) {
    $suspicious = true;
}
if (wafSanitizeValue($_POST, $blacklist, $matchedKeywords, $matchedFields, 'post', false)) {
    $suspicious = true;
}
if (wafSanitizeValue($_FILES, $blacklist, $matchedKeywords, $matchedFields, 'files', true)) {
    $suspicious = true;
}

$headerSnapshot = $originalSnapshot['headers'];
$headerKeywords = wafGetHeaderKeywords();
if (wafSanitizeValue($headerSnapshot, $headerKeywords, $matchedKeywords, $matchedFields, 'headers', false)) {
    $suspicious = true;
}

$rawBodyMatches = array();
list($sanitizedRawBody, $rawBodyChanged) = wafReplaceKeywordsInString($originalSnapshot['raw_body'], $blacklist, $rawBodyMatches);
if ($rawBodyChanged) {
    $suspicious = true;
    foreach ($rawBodyMatches as $keyword => $state) {
        $matchedKeywords[$keyword] = $state;
    }
    $matchedFields['raw_body'] = array_keys($rawBodyMatches);
}

$_REQUEST = array_merge($_COOKIE, $_GET, $_POST);
$get = $_GET;
$post = $_POST;
$file = $_FILES;
$request = $_REQUEST;

if ($suspicious || wafLogAll()) {
    saveRequest($originalSnapshot['raw_request']);
    // 注意 exit 只在确实命中拦截条件时执行：全量记录模式下正常请求不能被拦
    if ($suspicious && wafGetMode() === 2) {
        $redirect = wafGetRedirectPath();
        if (!headers_sent()) {
            header('Location: ' . $redirect, true, 302);
        }
        exit;
    }
}

if (!defined('PHPWAF_RESPONSE_BUFFER')) {
    define('PHPWAF_RESPONSE_BUFFER', true);
    ob_start('wafSanitizeResponse');
}
