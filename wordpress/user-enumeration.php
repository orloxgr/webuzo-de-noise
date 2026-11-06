<?php // Managed by webuzo-de-noise
/** Plugin Name: Webuzo De-Noise User Enumeration Guard
 * Version: 0.1.0
 * This owned MU plugin is installed/removed only when the feature is selected.
 */
namespace WebuzoDeNoise\UserEnumeration;
if (!defined('ABSPATH')) { exit; }
$flags = json_decode('__HDN_FLAGS__', true);
// Shared document roots can serve selected and unselected Webuzo domains.
if (is_array($flags['hosts'])) {
    $host = strtolower(rtrim(preg_replace('/:[0-9]+$/', '', $_SERVER['HTTP_HOST'] ?? ''), '.'));
    $selected = false;
    foreach ($flags['hosts'] as $allowed) {
        if ($host === $allowed || (strpos($allowed, '*.') === 0 &&
            $host !== substr($allowed, 2) && substr($host, -strlen(substr($allowed, 1))) === substr($allowed, 1))) {
            $selected = true; break;
        }
    }
    if (!$selected) { return; }
}

// WordPress has already checked cookies/nonces or application credentials here.
// Merely sending a Cookie or Authorization header never grants access.
add_filter('rest_pre_dispatch', static function ($result, $server, $request) use ($flags) {
    if ($flags['rest'] && in_array($request->get_method(), ['GET', 'HEAD'], true)
        && preg_match('~^/wp/v2/users(?:/[0-9]+)?/?$~i', $request->get_route())
        && !is_user_logged_in()) {
        return new \WP_Error('hdn_user_enumeration', 'Public user enumeration is disabled.', ['status' => 403]);
    }
    return $result;
}, -100, 3);

add_filter('rest_post_dispatch', static function ($response, $server, $request) use ($flags) {
    if ($flags['rest'] && preg_match('~^/wp/v2/users(?:/[0-9]+)?/?$~i', $request->get_route())) {
        $response->header('Cache-Control', 'no-store, private');
    }
    return $response;
}, 100, 3);

add_action('template_redirect', static function () use ($flags) {
    if (!is_user_logged_in() && is_author() && ($flags['author_archives'] ||
        ($flags['author_ids'] && isset($_GET['author'])))) {
        nocache_headers();
        status_header(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo 'Public user enumeration is disabled.';
        exit;
    }
}, 0);
