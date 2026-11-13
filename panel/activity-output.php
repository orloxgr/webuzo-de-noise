<?php if (!defined('SOFTACULOUS')) { http_response_code(403); exit; } ?>
<div id="hdn-activity-output">
<?php $activity = $data['analysis'] ?? null; if (is_array($activity)):
    $counts = ['blocked' => 0, 'matched' => 0, 'observed' => 0];
    $groups = [];
    foreach ($activity['rows'] ?? [] as $row) {
        $key = json_encode([$row['domain'], $row['rule'], $row['agent'] ?? null]);
        if (!isset($groups[$key])) $groups[$key] = ['domain' => $row['domain'], 'rule' => $row['rule'],
            'agent' => $row['agent'] ?? null, 'blocked' => 0, 'matched' => 0, 'observed' => 0, 'total' => 0];
        $count = (int)$row['count'];
        if (isset($counts[$row['outcome']])) {
            $counts[$row['outcome']] += $count;
            $groups[$key][$row['outcome']] += $count;
        }
        $groups[$key]['total'] += $count;
    }
    $groups = array_values($groups);
    usort($groups, static fn($a, $b) => $b['total'] <=> $a['total'] ?: strcmp($a['domain'] . $a['rule'], $b['domain'] . $b['rule']));
    $agentHtml = static function ($agent) use ($escape): string {
        if ($agent === null) return 'Not recorded';
        if ($agent === '') return 'Not sent';
        $label = $agent;
        if (preg_match('/\b(Googlebot(?:-[A-Za-z]+)?|bingbot|Applebot|DuckDuckBot|YandexBot|YisouSpider|Baiduspider|PetalBot|AhrefsBot|SemrushBot|GPTBot|ClaudeBot)\b/i', $agent, $match)) $label = $match[0] . ' (declared)';
        return '<details class="hdn-activity-agent-details"><summary title="' . $escape($agent) . '">' . $escape($label) . '</summary><div>' . $escape($agent) . '</div></details>';
    };
    $ruleHtml = static function ($rule) use ($escape): string {
        $labels = ['login' => 'WordPress login rate limit', 'xmlrpc' => 'XML-RPC rate limit',
            'agent' => 'User-Agent rule', 'private-file' => 'Private file protection',
            'global-ban' => 'Global website IP ban', 'domain-ban' => 'Domain IP ban', 'user-enumeration' => 'User enumeration',
            'wordpress-access' => 'WordPress access gate', 'country-filter' => 'Country filter',
            'captcha-check' => 'CAPTCHA shown / retried', 'captcha-verified' => 'CAPTCHA verified',
            'captcha-request' => 'CAPTCHA request',
            'missing-file' => 'Missing-file probe', 'suspicious-query' => 'Suspicious query',
            'endpoint-limit' => 'Endpoint rate limit'];
        $label = $labels[$rule] ?? (strpos($rule, 'filter-limit-') === 0 ? 'Filtered URL rate limit' :
            (strpos($rule, 'filter-block-') === 0 ? 'Filtered URL block' :
            (strpos($rule, 'static-') === 0 ? 'Missing static file rule' : $rule)));
        return $escape($label) . ($label !== $rule ? '<small class="hdn-activity-rule-id">' . $escape($rule) . '</small>' : '');
    };
    $outcomes = ['blocked' => 'Blocked', 'matched' => 'No block recorded', 'observed' => 'Observe only'];
    $domain = $activity['selected_domain'] ?? 'all';
?>
<p class="u-mb10"><strong>Saved review · <?= $escape($domain === 'all' ? 'All sites' : $domain) ?> · <?= $escape($activity['window_minutes']) ?>-minute window</strong></p>
<?php if (isset($activity['window_start'], $activity['window_end'])): ?>
<p class="u-mb10">From <time data-hdn-time datetime="<?= $escape($activity['window_start']) ?>"><?= $escape(str_replace('T', ' ', $activity['window_start'])) ?></time>
to <time data-hdn-time datetime="<?= $escape($activity['window_end']) ?>"><?= $escape(str_replace('T', ' ', $activity['window_end'])) ?></time>.</p>
<?php else: ?><p class="u-mb10">The exact time range was not saved in this older report. Refresh activity to record a new window.</p><?php endif; ?>
<?php if (!empty($activity['webmail'])): ?><p>Webmail matches use native logs, saved policy and response status.</p><?php endif; ?>
<div class="hdn-activity-counts u-mb20">
    <div><strong><?= $escape($activity['total']) ?></strong><span>Matched log records</span></div>
    <div><strong><?= $escape($counts['blocked']) ?></strong><span>Blocked by De-Noise</span></div>
    <div><strong><?= $escape($counts['matched']) ?></strong><span>No block recorded</span></div>
    <div><strong><?= $escape($counts['observed']) ?></strong><span>Observe only</span></div>
</div>
<p class="u-mb10">A rule match alone does not mean an attack or a block. Blocked means this request was rejected or rate-limited by De-Noise; it does not by itself mean an IP ban. HTTP status is the final response code.</p>
<p class="u-mb20">User-Agent names are declared by the client, not verified identities. Open a User-Agent to see its full value. Older records show “Not recorded”; an empty header shows “Not sent”.</p>
<h3 class="u-mb10">Summary by site, rule and User-Agent</h3>
<div class="hdn-table-scroll"><table class="table" data-hdn-list="Activity summary"><thead><tr><th>Site</th><th>Rule</th><th>User-Agent</th><th>Blocked</th><th>No block recorded</th><th>Observe only</th><th>Total</th></tr></thead><tbody>
<?php foreach ($groups as $row): ?><tr data-hdn-csv="<?= $escape(json_encode([$row['domain'],$row['rule'],$row['agent'] ?? '',$row['blocked'],$row['matched'],$row['observed'],$row['total']])) ?>">
<td><?= $escape($row['domain']) ?></td><td><?= $ruleHtml($row['rule']) ?></td>
<td class="hdn-activity-agent"><?= $agentHtml($row['agent']) ?></td>
<td><?= $escape($row['blocked']) ?></td><td><?= $escape($row['matched']) ?></td><td><?= $escape($row['observed']) ?></td><td><?= $escape($row['total']) ?></td></tr><?php endforeach; ?>
</tbody></table></div>
<?php if (!$groups): ?><p>No matching records for this site in the saved time window. This is not a total-traffic measurement.</p><?php endif; ?>
<h3 class="u-mt20 u-mb10">Individual log records</h3>
<?php $reviewPage = $activity; require __DIR__ . '/review-pagination.php'; ?>
<div class="hdn-table-scroll"><table class="table"><thead><tr><th>Time</th><th>Site</th><th>Rule</th><th>User-Agent</th><th>De-Noise result</th><th>HTTP status</th></tr></thead><tbody>
<?php foreach ($activity['findings'] ?? [] as $row): ?><tr>
<td><time data-hdn-time datetime="<?= $escape($row['time']) ?>"><?= $escape(str_replace('T', ' ', $row['time'])) ?></time></td><td><?= $escape($row['domain']) ?></td><td><?= $ruleHtml($row['rule']) ?></td><td class="hdn-activity-agent"><?= $agentHtml($row['agent'] ?? null) ?></td><td><?= $escape($outcomes[$row['outcome']] ?? $row['outcome']) ?></td><td><?= $escape($row['status']) ?></td>
</tr><?php endforeach; ?>
</tbody></table></div>

<?php endif; ?>
</div>
