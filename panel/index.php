<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }

// Rendered only by the authenticated native Webuzo plugin action.
$listing = [];
foreach (['bans'] as $scope) {
    $pageValue = $_POST[$scope . '_page'] ?? $_GET[$scope . '_page'] ?? 1;
    $viewValue = $_POST[$scope . '_view'] ?? $_GET[$scope . '_view'] ?? 'active';
    $listing[$scope . '_page'] = filter_var($pageValue, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) ?: 1;
    $listing[$scope . '_view'] = in_array($viewValue, ['active', 'history'], true) ? $viewValue : 'active';
}
$statusRequest = ['actor' => $actor, 'owner' => $owner, 'action' => 'status', 'listing' => $listing];
$listing['wordpress_page'] = filter_var($_POST['wordpress_target_page'] ?? $_POST['wordpress_page'] ?? $_GET['wordpress_page'] ?? 1,
    FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) ?: 1;
$statusRequest['listing'] = $listing;
$selectedTab = $_POST['tab'] ?? $_GET['tab'] ?? 'general';
$activeTab = is_string($selectedTab) ? $selectedTab : 'general';
$fields = static function (string $action) use ($escape, $activeTab, $listing, $csrf): void {
    echo '<input type="hidden" name="token" value="' . $escape($csrf) . '">';
    echo '<input type="hidden" name="action" value="' . $escape($action) . '">';
    echo '<input type="hidden" name="tab" value="' . $escape($activeTab) . '">';
    foreach ($listing as $key => $value) echo '<input type="hidden" name="' . $escape($key) . '" value="' . $escape($value) . '">';
};
$error = '';
$message = '';
$submitted = null;
$wordpressResult = null;
$analysisResult = null;
$fail2banResult = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ((!$isAdmin && !in_array($_POST['action'] ?? '', ['activity_start', 'activity_status', 'activity_cancel'], true)) || !empty($read_only) || !is_string($_POST['token'] ?? null) ||
        !hash_equals($csrf, $_POST['token'])) {
        $error = 'Write access and a valid request token are required.';
    } else {
        $request = array_merge($statusRequest, ['action' => is_string($_POST['action'] ?? null) ? $_POST['action'] : '']);
        if ($request['action'] === 'save') {
            $agents = is_string($_POST['agents'] ?? null) ? preg_split('/\r\n|\r|\n/', trim($_POST['agents'])) : [];
            $tools = is_string($_POST['tool_agents'] ?? null) ? preg_split('/\r\n|\r|\n/', trim($_POST['tool_agents'])) : [];
            $submitted = ['schema' => 11, 'mode' => $_POST['mode'] ?? '', 'agents' => array_values(array_filter($agents, static fn($line) => trim($line) !== '')),
                'log_rejections' => isset($_POST['log_rejections']), 'mail_protection' => isset($_POST['mail_protection']),
                'tool_agents' => array_values(array_filter($tools, static fn($line) => trim($line) !== '')),
                'agents_enabled' => isset($_POST['agents_enabled']), 'tool_agents_enabled' => isset($_POST['tool_agents_enabled']),
                'scanners' => isset($_POST['scanners'])];
            foreach (['ai_agents', 'search_agents', 'seo_agents'] as $field) {
                $lines = is_string($_POST[$field] ?? null) ? preg_split('/\r\n|\r|\n/', trim($_POST[$field])) : [];
                $submitted[$field] = array_values(array_filter($lines, static fn($line) => trim($line) !== ''));
                $submitted[$field . '_enabled'] = isset($_POST[$field . '_enabled']);
            }
            $submitted['enumeration'] = ['enabled' => isset($_POST['enumeration_enabled']),
                'rest' => isset($_POST['enumeration_rest']), 'author_ids' => isset($_POST['enumeration_author_ids']),
                'author_archives' => isset($_POST['enumeration_author_archives']),
                'targets' => $_POST['enumeration_targets'] ?? []];
            foreach (['login', 'xmlrpc'] as $key) {
                $submitted[$key] = ['enabled' => isset($_POST[$key . '_enabled']),
                    'rate' => filter_var($_POST[$key . '_rate'] ?? '', FILTER_VALIDATE_INT),
                    'burst' => filter_var($_POST[$key . '_burst'] ?? '', FILTER_VALIDATE_INT)];
            }
            $list = static function ($value, bool $lines = false): array {
                if (!is_string($value)) return [];
                return array_values(array_filter(array_map('trim', preg_split($lines ? '/\r\n|\r|\n/' : '/[\s,]+/', $value)), static fn($x) => $x !== ''));
            };
            $submitted['bans'] = ['enabled' => isset($_POST['bans_enabled']),
                'private_files' => isset($_POST['bans_private_files']), 'repositories' => isset($_POST['bans_repositories']),
                'maxretry' => filter_var($_POST['bans_maxretry'] ?? '', FILTER_VALIDATE_INT),
                'findtime' => filter_var($_POST['bans_findtime'] ?? '', FILTER_VALIDATE_INT),
                'duration_days' => filter_var($_POST['bans_duration_days'] ?? '', FILTER_VALIDATE_INT),
                'ignore_ips' => $list($_POST['bans_ignore_ips'] ?? '', true), 'targets' => $_POST['bans_targets'] ?? []];
            foreach (['missing_files' => 'paths', 'suspicious_queries' => 'targets'] as $key => $field) {
                $submitted['bans'][$key] = ['enabled' => isset($_POST['bans_' . $key . '_enabled']),
                    'maxretry' => filter_var($_POST['bans_' . $key . '_maxretry'] ?? '', FILTER_VALIDATE_INT),
                    'findtime' => filter_var($_POST['bans_' . $key . '_findtime'] ?? '', FILTER_VALIDATE_INT),
                    'duration_days' => filter_var($_POST['bans_' . $key . '_duration_days'] ?? '', FILTER_VALIDATE_INT),
                    $field => $list($_POST['bans_' . $key . '_list'] ?? '', true)];
            }
            $submitted['bans']['suspicious_queries']['parameters'] = $list($_POST['bans_suspicious_queries_parameters'] ?? '', true);
            $submitted['bans']['any_404'] = ['enabled' => isset($_POST['bans_any_404_enabled']),
                'exclude_static' => isset($_POST['bans_any_404_exclude_static']),
                'min_distinct_paths' => filter_var($_POST['bans_any_404_min_distinct_paths'] ?? '', FILTER_VALIDATE_INT),
                'maxretry' => filter_var($_POST['bans_any_404_maxretry'] ?? '', FILTER_VALIDATE_INT),
                'findtime' => filter_var($_POST['bans_any_404_findtime'] ?? '', FILTER_VALIDATE_INT),
                'duration_days' => filter_var($_POST['bans_any_404_duration_days'] ?? '', FILTER_VALIDATE_INT)];
            $submitted['probe_exceptions'] = [];
            foreach (['files', 'queries'] as $kind) {
                $submitted['probe_exceptions'][$kind] = [];
                $values = $_POST['probe_exceptions_' . $kind] ?? [];
                if (!is_array($values)) { $submitted['probe_exceptions'][$kind] = false; continue; }
                foreach ($values as $site => $paths) {
                    if (!is_string($paths)) { $submitted['probe_exceptions'][$kind] = false; break; }
                    $paths = $list($paths, true);
                    if ($paths) $submitted['probe_exceptions'][$kind][$site] = $paths;
                }
            }
            $submitted['static_exceptions'] = [];
            if (!is_array($_POST['static_exceptions'] ?? [])) { $submitted['static_exceptions'] = false; }
            else {
                foreach ($_POST['static_exceptions'] ?? [] as $site => $paths) {
                    if (!is_string($paths)) { $submitted['static_exceptions'] = false; break; }
                    $paths = $list($paths, true);
                    if ($paths) $submitted['static_exceptions'][$site] = $paths;
                }
            }
            foreach (['filters', 'static'] as $module) {
                $submitted[$module] = [];
                if (!is_array($_POST[$module] ?? [])) { $submitted[$module] = false; continue; }
                foreach ($_POST[$module] ?? [] as $row) {
                    $row = is_array($row) ? $row : [];
                    $rule = ['id' => $row['id'] ?? '', 'enabled' => isset($row['enabled']),
                        'path' => $row['path'] ?? '', 'targets' => $row['targets'] ?? []];
                    if ($module === 'filters') {
                        $rule += ['parameters' => $list($row['parameters'] ?? ''),
                            'agents' => $list($row['agents'] ?? '', true), 'action' => $row['rule_action'] ?? '',
                            'rate' => filter_var($row['rate'] ?? '', FILTER_VALIDATE_INT),
                            'burst' => filter_var($row['burst'] ?? '', FILTER_VALIDATE_INT)];
                    } else { $rule['extensions'] = $list(strtolower((string)($row['extensions'] ?? ''))); }
                    $submitted[$module][] = $rule;
                }
            }
            $request['policy'] = $submitted;
            if (is_array($submitted['static_exceptions'])) $request['policy']['static_exceptions'] = (object)$submitted['static_exceptions'];
            foreach (['files', 'queries'] as $kind) {
                if (is_array($submitted['probe_exceptions'][$kind])) $request['policy']['probe_exceptions'][$kind] = (object)$submitted['probe_exceptions'][$kind];
            }
        } elseif ($request['action'] === 'agents_export') {
            $request['job'] = $_POST['analysis_job'] ?? '';
            $request['offset'] = filter_var($_POST['export_offset'] ?? 0, FILTER_VALIDATE_INT);
        } elseif ($request['action'] === 'activity_start') {
            $request['minutes'] = filter_var($_POST['analysis_minutes'] ?? '', FILTER_VALIDATE_INT);
        } elseif (in_array($request['action'], ['log_scan', 'log_scan_start', 'agents_start', 'php_files_start'], true)) {
            $request['target'] = $_POST['analysis_target'] ?? '';
            $request['minutes'] = filter_var($_POST['analysis_minutes'] ?? '', FILTER_VALIDATE_INT);
            $request['verify_google'] = isset($_POST['analysis_verify_google']);
        } elseif (in_array($request['action'], ['log_scan_status', 'log_scan_cancel', 'activity_status', 'activity_cancel', 'agents_status', 'agents_cancel', 'php_files_status', 'php_files_cancel'], true)) {
            $request['job'] = $_POST['analysis_job'] ?? '';
            $request['page'] = filter_var($_POST['analysis_page'] ?? 1, FILTER_VALIDATE_INT);
        } elseif ($request['action'] === 'history_clear') {
            $request['scope'] = $_POST['history_scope'] ?? '';
        } elseif ($request['action'] === 'history_settings_save') {
            $request['days'] = filter_var($_POST['history_days'] ?? '', FILTER_VALIDATE_INT);
        } elseif ($request['action'] === 'fail2ban_save') {
            $request['settings'] = [];
            $values = $_POST['services'] ?? [];
            if (!is_array($values) || array_diff(array_keys($values), ['ssh', 'imap', 'smtp', 'ftp'])) { $request['settings'] = false; }
            else foreach (['ssh', 'imap', 'smtp', 'ftp'] as $service) {
                $row = $values[$service] ?? [];
                if (!is_array($row) || !is_string($row['ignore_ips'] ?? null)) { $request['settings'] = false; break; }
                $request['settings'][$service] = ['enabled' => isset($row['enabled']),
                    'maxretry' => filter_var($row['maxretry'] ?? '', FILTER_VALIDATE_INT),
                    'findtime' => filter_var($row['findtime'] ?? '', FILTER_VALIDATE_INT),
                    'bantime' => filter_var($row['bantime'] ?? '', FILTER_VALIDATE_INT),
                    'ignore_ips' => array_values(array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', $row['ignore_ips'])), static fn($v) => $v !== ''))];
            }
        } elseif (in_array($request['action'], ['fail2ban_test', 'fail2ban_unban'], true)) {
            $request['service'] = $_POST['service'] ?? '';
            if ($request['action'] === 'fail2ban_unban') $request['ips'] = $_POST['service_ips'] ?? [];
        } elseif ($request['action'] === 'fail2ban_install_start') {
            $request['plan_token'] = $_POST['plan_token'] ?? '';
        } elseif ($request['action'] === 'wordpress_save') {
            $integer = static fn($key) => filter_var($_POST[$key] ?? '', FILTER_VALIDATE_INT);
            $third = $integer('wordpress_third_days');
            $request['settings'] = ['enabled' => isset($_POST['wordpress_enabled']),
                'maxretry' => $integer('wordpress_maxretry'),
                'findtime' => $integer('wordpress_window_minutes') * 60,
                'durations' => [$integer('wordpress_first_minutes') * 60,
                    $integer('wordpress_second_days') * 86400, $third === 0 ? -1 : $third * 86400]];
        } elseif ($request['action'] === 'wordpress_unban') {
            $request['ips'] = isset($_POST['wordpress_unban_all']) ? 'all' : ($_POST['wordpress_ips'] ?? []);
        } elseif ($request['action'] === 'bulk') {
            $request['targets'] = $_POST['targets'] ?? [];
            $request['mode'] = $_POST['bulk_mode'] ?? '';
        } elseif ($request['action'] === 'unban') {
            $request['ips'] = isset($_POST['unban_all']) ? 'all' : ($_POST['ips'] ?? []);
        } elseif ($request['action'] === 'cron_preview') {
            $request['minimum'] = filter_var($_POST['cron_min'] ?? '', FILTER_VALIDATE_INT);
            $request['maximum'] = filter_var($_POST['cron_max'] ?? '', FILTER_VALIDATE_INT);
        } elseif ($request['action'] === 'cron_apply') {
            $request['plan_id'] = $_POST['plan_id'] ?? '';
            $request['jobs'] = $_POST['cron_jobs'] ?? [];
            $request['restore'] = isset($_POST['restore_cron']);
        }
        if (!in_array($request['action'], ['fail2ban_status', 'fail2ban_start', 'fail2ban_save', 'fail2ban_test', 'fail2ban_unban', 'fail2ban_install_preview', 'fail2ban_install_start', 'fail2ban_install_status', 'save', 'bulk', 'disable', 'sync', 'unban', 'cron_preview', 'cron_apply', 'wordpress_status', 'wordpress_save', 'wordpress_unban', 'history_clear', 'history_settings_save', 'log_scan', 'log_scan_start', 'log_scan_status', 'log_scan_cancel', 'activity_start', 'activity_status', 'activity_cancel', 'agents_start', 'agents_status', 'agents_cancel', 'agents_export', 'php_files_start', 'php_files_status', 'php_files_cancel'], true)) {
            $error = 'Unsupported operation.';
        } else {
            $isReview = strpos($request['action'], 'fail2ban_') === 0 || strpos($request['action'], 'log_scan_') === 0 || strpos($request['action'], 'activity_') === 0 || strpos($request['action'], 'agents_') === 0 || strpos($request['action'], 'php_files_') === 0;
            $result = $bridge($request);
            if ($isReview && ($_SERVER['HTTP_X_HDN_ANALYSIS'] ?? '') === '1') {
                if (!empty($result['job']['analysis'])) {
                    $data = ['analysis' => $result['job']['analysis']];
                    ob_start();
                    $reviewKind = $result['job']['analysis']['inventory_kind'] ?? null;
                    require $install . ($reviewKind ? '/panel/inventory-output.php' : (strpos($request['action'], 'activity_') === 0 ? '/panel/activity-output.php' : '/panel/analysis-output.php'));
                    unset($reviewKind);
                    $result['report'] = ob_get_clean();
                    unset($result['job']['analysis']);
                }
                if (!empty($result['ok']) && $request['action'] === 'fail2ban_status') {
                    $data = $result;
                    ob_start(); require $install . '/panel/fail2ban.php'; $result['report'] = ob_get_clean();
                }
                header('Content-Type: application/json; charset=utf-8');
                header('Cache-Control: private, no-store');
                if (empty($result['ok'])) http_response_code(400);
                echo json_encode($result, JSON_THROW_ON_ERROR); exit;
            }
            foreach (['fail2ban', 'install_job', 'install_plan', 'filter_test', 'service_result'] as $key) if (isset($result[$key])) $fail2banResult[$key] = $result[$key];
            if (isset($result['wordpress'])) $wordpressResult = $result['wordpress'];
            if ($request['action'] === 'log_scan' && !empty($result['ok'])) $analysisResult = $result['analysis'] ?? null;
            if (empty($result['ok'])) $error = $result['error'] ?? 'The operation failed.';
            elseif ($request['action'] === 'history_clear') $message = 'Completed ban history cleared. Active bans and strike counters are unchanged.';
            elseif ($request['action'] === 'history_settings_save') $message = 'History retention saved.';
            elseif ($request['action'] === 'log_scan') $message = 'Log review completed. Suggestions only; no protection settings or bans were changed.';
            elseif (strpos($request['action'], 'fail2ban_') === 0) $message = ['fail2ban_save' => 'Service protection applied.', 'fail2ban_test' => 'Filter test completed; no protection settings changed.', 'fail2ban_unban' => 'Selected service bans removed.', 'fail2ban_install_preview' => 'Installation preview ready; no packages changed.', 'fail2ban_install_start' => 'Fail2ban installation started.'][$request['action']] ?? 'Fail2ban status refreshed.';
            elseif (strpos($request['action'], 'wordpress_') === 0) $message = [
                'wordpress_save' => 'WordPress login protection applied through Fail2ban.',
                'wordpress_unban' => 'Selected WordPress IP bans removed.',
            ][$request['action']] ?? 'WordPress login protection status refreshed.';
            else $message =                 ($request['action'] === 'cron_preview' ? 'Cron preview generated. No schedule has changed.' :
                ($request['action'] === 'cron_apply' ? 'Selected cron schedules updated through Webuzo.' :
                ($request['action'] === 'disable' ? 'De-Noise is off for every domain. Its web bans will be released by synchronization.' :
                ($request['action'] === 'unban' ? 'Unban requested. Check the active and pending counts.' : 'Settings applied. Automatic bans synchronize within about one minute.'))));
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405); exit;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_SERVER['HTTP_X_HDN_ANALYSIS'] ?? '') === '1') {
    header('Content-Type: application/json; charset=utf-8'); http_response_code(403);
    echo json_encode(['ok' => false, 'error' => $error ?: 'Review request rejected.']); exit;
}
$data = $bridge($statusRequest);
foreach ($fail2banResult as $key => $value) $data[$key] = $value;
if ($wordpressResult !== null) $data['wordpress'] = $wordpressResult;
if ($isAdmin && $analysisResult !== null) $data['analysis'] = $analysisResult;
if (empty($data['ok'])) $error = $error ?: ($data['error'] ?? 'Could not load De-Noise.');
// When impersonating a user, render the user's scope even for an admin session.
if (!$isAdmin) $data['sites'] = array_values(array_filter($data['sites'] ?? [], static fn($site) => $site['owner'] === $owner));
$policy = $error !== '' && $submitted !== null ? $submitted : ($data['policy'] ?? []);
require $install . '/panel/view.php';
