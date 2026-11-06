<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }
?>
<div id="hdn-activity-output">
<?php $activity = $data['analysis'] ?? null; if (is_array($activity)): ?>
<p class="u-mb10">Matched requests · last <?= $escape($activity['window_minutes']) ?> minutes · <?= $escape($activity['total']) ?> in available retained logs</p>
<p class="u-mb10">User-Agent is the value declared by the client. Older records show “Not recorded”; an empty header shows “Not sent”.</p>
<?php if (!empty($activity['webmail'])): ?><p class="u-mb10"><?= !empty($activity['webmail']['available']) ? 'Webmail matches use native logs, saved policy and response status. Policy transition seconds are shown as matched.' : 'Native webmail activity logs are unavailable.' ?></p><?php endif; ?>
<div class="hdn-table-scroll"><table class="table"><thead><tr><th>Domain</th><th>Rule</th><th>User-Agent</th><th>Outcome</th><th>Requests</th></tr></thead><tbody>
<?php foreach ($activity['rows'] ?? [] as $row): ?><tr>
<td><?= $escape($row['domain']) ?></td><td><?= $escape($row['rule']) ?></td>
<td class="hdn-activity-agent"><?= $escape(!isset($row['agent']) ? 'Not recorded' : ($row['agent'] === '' ? 'Not sent' : $row['agent'])) ?></td>
<td><?= $escape($row['outcome']) ?></td><td><?= $escape($row['count']) ?></td></tr><?php endforeach; ?>
</tbody></table></div>
<?php if (empty($activity['rows'])): ?><p>No matching requests in this time window.</p><?php endif; ?>
<div class="hdn-table-scroll"><table class="table"><thead><tr><th>Time</th><th>Domain</th><th>Rule</th><th>User-Agent</th><th>Outcome</th><th>Status</th></tr></thead><tbody>
<?php foreach ($activity['findings'] ?? [] as $row): ?><tr>
<td><?= $escape($row['time']) ?></td><td><?= $escape($row['domain']) ?></td><td><?= $escape($row['rule']) ?></td><td class="hdn-activity-agent"><?= $escape(!isset($row['agent']) ? 'Not recorded' : ($row['agent'] === '' ? 'Not sent' : $row['agent'])) ?></td><td><?= $escape($row['outcome']) ?></td><td><?= $escape($row['status']) ?></td>
</tr><?php endforeach; ?>
</tbody></table></div>
<p>Page <?= $escape($activity['page'] ?? 1) ?> of <?= $escape($activity['pages'] ?? 1) ?></p>
<?php if (($activity['page'] ?? 1) > 1): ?><button type="button" class="button button-secondary" title="Read this result page without restarting the review or changing protection settings." data-hdn-analysis-page="<?= $escape($activity['page'] - 1) ?>">Previous</button><?php endif; ?>
<?php if (($activity['page'] ?? 1) < ($activity['pages'] ?? 1)): ?><button type="button" class="button button-secondary" title="Read this result page without restarting the review or changing protection settings." data-hdn-analysis-page="<?= $escape($activity['page'] + 1) ?>">Next</button><?php endif; ?>
<?php endif; ?>
</div>
