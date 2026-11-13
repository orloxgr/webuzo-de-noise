<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }
$analysis = $data['analysis'] ?? null;
$kind = $analysis['inventory_kind'] ?? $reviewKind;
$prefix = 'hdn-' . $kind;
?>
<div id="<?= $escape($prefix) ?>-output" data-hdn-inventory="<?= $escape($kind) ?>">
<?php if (is_array($analysis) && ($analysis['inventory_kind'] ?? '') === $kind): ?>
<?php if ($kind === 'php_files'): ?><p class="u-mt20 u-mb10">PHP 404 requests grouped by repeated directory paths. Open a group to select exact paths; no wildcard ban rule is created. A 404 alone does not establish malicious traffic.</p><?php endif; ?>
<h4 class="u-mt20 u-mb10">Analysis results · <?= $escape($analysis['minutes']) ?> minutes</h4>
<p class="u-mb10">Log records: <?= $escape($analysis['totals']['requests'] ?? 0) ?> · Domains: <?= $escape($analysis['domains']) ?> · <?= $kind === 'php_files' ? 'Groups' : 'Entries' ?>: <?= $escape($analysis['findings_total']) ?><?php if ($kind === 'php_files' && isset($analysis['paths_total'])): ?> · Exact paths: <?= $escape($analysis['paths_total']) ?><?php endif; ?> · <?= $escape(round($analysis['bytes_read'] / 1048576, 2)) ?> MiB read.</p>
<p class="u-mb10"><?= !empty($analysis['partial']) ? 'Incomplete coverage. See the log coverage below.' : 'Available retained logs processed in full.' ?> <?= $escape($analysis['note']) ?></p>
<?php if ($kind === 'php_files') require __DIR__ . '/review-filters.php'; ?>
<?php $reviewPage = $analysis; require __DIR__ . '/review-pagination.php'; ?>
<div class="hdn-inventory-actions u-mb10">
<label><input type="checkbox" data-hdn-select-inventory> Select this page</label>
<button type="button" class="button button-secondary" data-hdn-append-selected>Append selected to lists</button>

</div>
<p data-hdn-append-status role="status" class="u-mb10"></p>
<div class="hdn-scoped-table-wrap"><table class="table hdn-inventory-table"><thead><tr><th>Select</th><th><?= $kind === 'agents' ? 'Declared agent' : 'PHP path · HTTP 404' ?></th><th><?= $kind === 'agents' ? 'Bot information' : 'Interpretation / evidence' ?></th><th>Hits</th><th>Source domains / hits</th><th>Append to</th></tr></thead><tbody>
<?php foreach ($analysis['findings'] ?? [] as $row): ?>
<tr data-hdn-inventory-row>
<td><input type="checkbox" data-hdn-inventory-value="<?= $escape($row['candidate'] ?? '') ?>" <?= empty($row['candidate']) ? 'disabled' : '' ?> aria-label="Select <?= $escape($row['value'] ?: 'empty agent') ?>"></td>
<td><code><?= $escape($row['value'] === '' || $row['value'] === '-' ? 'Not sent' : $row['value']) ?></code></td>
<?php if ($kind === 'agents'): $info = $row['bot_info'] ?? []; ?>
<td class="hdn-bot-info">
<strong><?= $escape($info['operator'] ?? 'Not identified') ?></strong>
<p><?= $escape($info['purpose'] ?? 'Purpose not identified from this User-Agent.') ?></p>
<p><strong>Useful for:</strong> <?= $escape($info['usefulness'] ?? 'Review the requested URLs before blocking.') ?></p>
<?php if (is_string($info['url'] ?? null) && strpos($info['url'], 'https://') === 0): ?><a href="<?= $escape($info['url']) ?>" target="_blank" rel="noopener noreferrer">Source</a><?php endif; ?>
</td>
<?php else: $info = $row['php_info'] ?? []; ?>
<td class="hdn-bot-info"><strong><?= $escape($info['label'] ?? 'PHP 404') ?></strong><?php $reviewRow = $row; require __DIR__ . '/review-info.php'; ?>
<?php if (isset($row['clients'])): ?><p>Distinct clients: <?= $escape($row['clients']) ?></p><?php endif; ?>
<?php if (isset($row['first'], $row['last'])): ?><p><?= $escape(gmdate('Y-m-d H:i:s', (int)$row['first'])) ?> – <?= $escape(gmdate('Y-m-d H:i:s', (int)$row['last'])) ?> UTC</p><?php endif; ?>
<?php if (!empty($row['agents'])): ?><details><summary>Declared agents (<?= count($row['agents']) ?>)</summary><table class="table" data-hdn-list="PHP requesting agents"><thead><tr><th>Agent</th><th>Hits</th></tr></thead><tbody><?php foreach ($row['agents'] as $evidence): ?><tr><td><?= $escape($evidence['agent'] ?: 'Not sent') ?></td><td><?= $escape($evidence['count']) ?></td></tr><?php endforeach; ?></tbody></table></details><?php endif; ?>
</td>
<?php endif; ?>
<td><?= $escape($row['count']) ?></td>
<td><details><summary><?= $escape(count($row['domains'])) ?> domain(s)</summary><table class="table" data-hdn-list="Source domains"><thead><tr><th>Domain</th><th>Hits</th></tr></thead><tbody><?php foreach ($row['domains'] as $domain): ?><tr><td><?= $escape($domain['domain']) ?></td><td><?= $escape($domain['count']) ?></td></tr><?php endforeach; ?></tbody></table></details></td>
<td><?php if ($kind === 'agents'): ?>
<select class="form-select" data-hdn-inventory-field aria-label="Destination list for <?= $escape($row['value']) ?>">
<?php foreach ($analysis['categories'] as $field => $title): ?>
<option value="<?= $escape($field) ?>" <?= $row['category'] === $field ? 'selected' : '' ?>><?= $escape($title) ?></option>
<?php endforeach; ?></select>
<?php else: ?><span><?= !empty($row['members']) ? 'Open exact paths below' : 'Selected PHP files' ?></span><input type="hidden" data-hdn-inventory-field value="bans-missing_files-list"><?php endif; ?>
<?php if (empty($row['candidate']) && empty($row['members'])): ?><small><?= $escape($row['php_info']['append_reason'] ?? 'This value cannot be used as a literal rule.') ?></small><?php endif; ?><?php if ($kind === 'php_files' && empty($row['members'])) { $reviewRow = $row; require __DIR__ . '/review-note-controls.php'; } ?></td>
</tr>
<?php if (!empty($row['members'])): ?><tr><td colspan="6"><details><summary><?= count($row['members']) ?> exact paths · <?= $escape($row['count']) ?> hits</summary>
<table class="table" data-hdn-list="Exact PHP paths"><thead><tr><th>Select</th><th>PHP path</th><th>Interpretation / evidence</th><th>Hits</th><th>Source domains / hits</th><th>Append / review</th></tr></thead><tbody><?php foreach ($row['members'] as $pathRow) require __DIR__ . '/php-path-row.php'; ?></tbody></table>
</details></td></tr><?php endif; ?>
<?php endforeach; ?>
</tbody></table></div>
<?php if (empty($analysis['findings'])): ?><p class="u-mt10">No <?= $kind === 'agents' ? 'agent records' : 'PHP-path 404 records' ?> in the selected logs and time window.</p><?php endif; ?>

<details class="u-mt20"><summary>Log coverage</summary>
<p><?= $escape($analysis['totals']['unparsed'] ?? 0) ?> malformed lines · <?= $escape($analysis['totals']['incomplete_lines'] ?? 0) ?> incomplete trailing lines skipped.</p>
<?php foreach ($analysis['unavailable_domains'] ?? [] as $domain): ?><p>No readable log: <?= $escape($domain) ?></p><?php endforeach; ?>
<?php foreach ($analysis['errors'] ?? [] as $row): ?><p><?= $escape($row['domain'] . ' · ' . $row['file'] . ': ' . $row['message']) ?></p><?php endforeach; ?>
<table class="table" data-hdn-list="Inventory log coverage"><thead><tr><th>Domain / native log</th><th>Records</th><th>Coverage</th></tr></thead><tbody>
<?php foreach ($analysis['coverage'] ?? [] as $row): ?><tr><td><?= $escape($row['domain'] . ' · ' . $row['source'] . '/' . $row['file']) ?></td><td><?= $escape($row['records']) ?></td><td><?= $escape($row['note']) ?></td></tr><?php endforeach; ?></tbody></table>
</details>
<?php endif; ?>
</div>
