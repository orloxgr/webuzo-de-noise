<?php $scopedBans = $data['domain_bans'] ?? []; $canDomainEdit = !empty($scopedBans['can_edit']); $editableSites = 0; ?>
<h2 class="u-mb20">Domain automatic bans</h2>
<p class="u-mb20">Enable additional protection for selected domains. These bans affect web traffic to that domain and its aliases only. Administrator rules always apply; trigger lists, thresholds and exceptions are managed by the administrator.</p>
<?php if (!empty($scopedBans['error'])): ?><div class="alert alert-danger u-mb20"><?= $escape($isAdmin ? $scopedBans['error'] : 'Domain ban status is temporarily unavailable.') ?></div><?php endif; ?>
<?php foreach (['missing_files' => 'Selected nonexistent PHP files', 'suspicious_queries' => 'Suspicious secret-file queries', 'any_404' => 'General 404 responses'] as $kind => $title):
    $limits = $scopedBans['limits'][$kind] ?? []; ?>
<p class="u-mb10"><strong><?= $escape($title) ?>:</strong> <?= $escape($limits['maxretry'] ?? ($kind === 'any_404' ? 10 : 2)) ?> <?= $kind === 'missing_files' ? 'distinct file paths' : 'matching requests' ?> in <?= $escape($limits['findtime'] ?? ($kind === 'any_404' ? 300 : 60)) ?> seconds; <?= !isset($limits['duration_days']) ? '3-day ban' : (empty($limits['duration_days']) ? 'permanent ban' : $escape($limits['duration_days']) . '-day ban') ?>.</p>
<?php endforeach; ?>
<?php if (!$canDomainEdit): ?><p class="u-mb20">Editing is disabled by the administrator.</p><?php endif; ?>
<form method="post"><?php $fields('domain_bans_save'); ?>
<?php foreach ($data['sites'] ?? [] as $site):
    if (($site['kind'] ?? 'web') === 'mail') continue;
    $preferences = $scopedBans['preferences'][$site['key']] ?? [];
    $available = $site['supported'] && !$site['suspended']; $editableSites += (int)$available; ?>
<div class="box-collapse u-mb10"><div class="box-collapse-content">
<h3 class="u-mb10"><?= $escape($site['domain']) ?> · <?= $escape($site['owner']) ?></h3>
<p class="u-mb10">Mode: <?= $escape($available ? ucfirst($site['mode']) : 'Unavailable') ?></p>
<?php if ($available): ?>
<input type="hidden" name="domain_preferences[<?= $escape($site['key']) ?>][present]" value="1">
<?php foreach (['missing_files' => 'Automatic bans for selected file probes', 'suspicious_queries' => 'Automatic bans for suspicious queries', 'any_404' => 'Automatic bans for repeated 404 responses'] as $kind => $title): ?>
<label class="form-label u-block u-mb10"><input type="checkbox" name="domain_preferences[<?= $escape($site['key']) ?>][<?= $kind ?>]" <?= !empty($preferences[$kind]) ? 'checked' : '' ?> <?= !$canDomainEdit ? 'disabled' : '' ?>> <?= $escape($title) ?></label>
<?php endforeach; ?>
<?php endif; ?></div></div>
<?php endforeach; ?>
<?php if ($canDomainEdit && $editableSites): ?><button class="button u-mt10" type="submit">Save domain protection</button><?php endif; ?>
</form>
<h3 class="u-mt20 u-mb10">Domain ban status</h3>
<p class="u-mb10">Active: <?= $escape($scopedBans['active'] ?? 0) ?> · Pending: <?= $escape($scopedBans['pending'] ?? 0) ?></p>
<?php $listState = $scopedBans; $listPrefix = 'domain'; $listTab = 'domain-bans'; require $install . '/panel/ban-pagination.php'; ?>
<div class="hdn-scoped-table-wrap"><table class="table"><thead><tr><th>Domain</th><th>IP</th><th>Reason</th><th>Recorded (UTC)</th><th>Expiry (UTC)</th><th><?= $historyView ? 'Ended (UTC)' : 'Status' ?></th></tr></thead><tbody>
<?php foreach ($scopedBans['rows'] ?? [] as $row): ?><tr>
<td><?= $escape($row['domain']) ?></td><td><?= $escape($row['ip']) ?></td><td><?= $escape(['domain-file' => 'Selected file probes', 'domain-query' => 'Suspicious queries', 'domain-404' => 'Repeated 404 responses'][$row['reason']] ?? $row['reason']) ?><?php require $install . '/panel/ban-details.php'; ?></td>
<td><?= $escape(gmdate('Y-m-d H:i:s', (int)$row['created'])) ?></td>
<td><?= $row['expires'] ? $escape(gmdate('Y-m-d H:i:s', (int)$row['expires'])) : 'Permanent' ?></td><td><?= $historyView ? $escape(gmdate('Y-m-d H:i:s', (int)$row['ended'])) : $escape($row['status']) ?></td>
</tr><?php endforeach; ?></tbody></table></div>
<?php if (empty($scopedBans['rows'])): ?><p>No domain-specific bans to display.</p><?php endif; ?>
