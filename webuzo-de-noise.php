<?php
/*
Plugin Name: Webuzo De-Noise
Version: 0.2.2
Description: Filter unwanted web requests and manage domain protection.
Author: Byron Iniotakis
Author URI: https://www.iniotakis.com
License: GPL-3.0-or-later
*/
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }

register_activation_hook(__FILE__, 'wdn_activate');
register_deactivation_hook(__FILE__, 'wdn_deactivate');

function wdn_command(string $operation): array {
    global $W;
    if (!in_array($operation, ['install', 'remove'], true)) throw new InvalidArgumentException('Invalid lifecycle operation.');
    $result = $W->wexec('/usr/bin/python3 -I -B ' . escapeshellarg(__DIR__ . '/src/lifecycle.py') . ' ' . $operation);
    $data = json_decode(implode("\n", $result['output'] ?? []), true);
    if (($result['retval'] ?? 1) !== 0 || !is_array($data) || empty($data['ok'])) {
        throw new RuntimeException(is_array($data) ? ($data['error'] ?? 'De-Noise operation failed.') : 'De-Noise returned an invalid response.');
    }
    return $data;
}
function wdn_activate() {
    global $error;
    try { wdn_command('install'); return true; }
    catch (Throwable $exception) { $error[] = $exception->getMessage(); return false; }
}
function wdn_deactivate() {
    global $error;
    try { wdn_command('remove'); return true; }
    catch (Throwable $exception) { $error[] = $exception->getMessage(); return false; }
}

add_filter('admin_menu', 'wdn_admin_menu', 10, 1);
function wdn_admin_menu($menu) {
    $menu['webuzo-de-noise'] = ['name'=>'De-Noise', 'href'=>'index.php?act=webuzo-de-noise', 'icon'=>'fas fa-shield-alt'];
    return $menu;
}
add_filter('enduser_cats_icons', 'wdn_user_menu', 10, 1);
function wdn_user_menu($menu) {
    $menu['security']['icons']['webuzo-de-noise'] = ['name'=>'De-Noise', 'href'=>'index.php?act=webuzo-de-noise', 'icon'=>'fas fa-shield-alt'];
    return $menu;
}
admin_act('webuzo-de-noise', 'wdn_page');
enduser_act('webuzo-de-noise', 'wdn_page');
function wdn_page() {
    // Native action callbacks run before the panel emits its HTML header.
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && ($_SERVER['HTTP_X_HDN_ANALYSIS'] ?? '') === '1') {
        wdn_theme(); exit;
    }
    theme_for_act('wdn_theme', 'webuzo-de-noise');
}

function wdn_bridge(array $request): array {
    global $W;
    $identity = bin2hex(random_bytes(32));
    $path = '/run/webuzo-de-noise/' . $identity . '.json';
    $payload = json_encode($request, JSON_THROW_ON_ERROR);
    if (strlen($payload) > 1024 * 1024) throw new RuntimeException('The settings exceed the safe request size.');
    $previous = umask(0077);
    try { $handle = fopen($path, 'x'); }
    finally { umask($previous); }
    if ($handle === false) throw new RuntimeException('De-Noise is not active. Contact the hosting administrator.');
    try {
        $offset = 0;
        while ($offset < strlen($payload)) {
            $written = fwrite($handle, substr($payload, $offset));
            if ($written === false || $written === 0) throw new RuntimeException('Could not send the De-Noise request.');
            $offset += $written;
        }
        fclose($handle); $handle = null;
        $result = $W->wexec('/usr/bin/python3 -I -B ' . escapeshellarg(__DIR__ . '/src/addon.py') . ' --request ' . $identity);
        $data = json_decode(implode("\n", $result['output'] ?? []), true);
        if (!is_array($data)) return ['ok'=>false,'error'=>'De-Noise returned an invalid response.'];
        return $data;
    } finally {
        if (is_resource($handle)) fclose($handle);
        if (is_file($path)) unlink($path);
    }
}

function wdn_theme() {
    global $SESS, $user, $globals;
    $actor = $SESS['user'] ?? '';
    if (!is_string($actor) || !preg_match('/^[A-Za-z0-9][A-Za-z0-9_-]*$/D', $actor)) {
        http_response_code(403); return;
    }
    $isAdmin = $actor === 'root' && empty($SESS['is_reseller']);
    $owner = $actor;
    $install = __DIR__;
    $meta = json_decode(file_get_contents(__DIR__ . '/info.json'), true, 16, JSON_THROW_ON_ERROR);
    $read_only = !empty($user['demo']) || !empty($globals['demo']);
    $csrf = $SESS['token'] ?? '';
    if (!is_string($csrf) || $csrf === '') { http_response_code(403); return; }
    $bridge = static function(array $request): array {
        try { return wdn_bridge($request); }
        catch (Throwable $exception) { return ['ok'=>false,'error'=>$exception->getMessage()]; }
    };
    $escape = static fn($value) => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    require __DIR__ . '/panel/index.php';
}
