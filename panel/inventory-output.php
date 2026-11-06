<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }
$analysis = $data['analysis'] ?? null;
$kind = $analysis['inventory_kind'] ?? $reviewKind;
$prefix = 'hdn-' . $kind;
?>
<div id="<?= $escape($prefix) ?>-output" data-hdn-inventory="<?= $escape($kind) ?>">
<?php if (is_array($analysis) && ($analysis['inventory_kind'] ?? '') === $kind): ?>
<h4 class="u-mt20 u-mb10">Analysis results · <?= $escape($analysis['minutes']) ?> minutes</h4>
<p class="u-mb10">Log records: <?= $escape($analysis['totals']['requests'] ?? 0) ?> · Domains: <?= $escape($analysis['domains']) ?> · Entries: <?= $escape($analysis['findings_total']) ?> · <?= $escape(round($analysis['bytes_read'] / 1048576, 2)) ?> MiB read.</p>
<p class="u-mb10"><?= !empty($analysis['partial']) ? 'Incomplete coverage. See the log coverage below.' : 'Available retained logs processed in full.' ?> <?= $escape($analysis['note']) ?></p>
<div class="hdn-inventory-actions u-mb10">
<label><input type="checkbox" data-hdn-select-inventory> Select this page</label>
<button type="button" class="button button-secondary" data-hdn-append-selected>Append selected to lists</button>
</div>
<p data-hdn-append-status role="status" class="u-mb10"></p>
<div class="hdn-scoped-table-wrap"><table class="table hdn-inventory-table"><thead><tr><th>Select</th><th><?= $kind === 'agents' ? 'Declared agent' : 'PHP path · HTTP 404' ?></th><th>Hits</th><th>Source domains / hits</th><th>Append to</th></tr></thead><tbody>
<?php foreach ($analysis['findings'] ?? [] as $row): ?>
<tr data-hdn-inventory-row>
<td><input type="checkbox" data-hdn-inventory-value="<?= $escape($row['candidate'] ?? '') ?>" <?= empty($row['candidate']) ? 'disabled' : '' ?> aria-label="Select <?= $escape($row['value'] ?: 'empty agent') ?>"></td>
<td><code><?= $escape($row['value'] === '' || $row['value'] === '-' ? 'Not sent' : $row['value']) ?></code></td>
<td><?= $escape($row['count']) ?></td>
<td><details><summary><?= $escape(count($row['domains'])) ?> domain(s)</summary><?php foreach ($row['domains'] as $domain): ?><div><?= $escape($domain['domain']) ?> · <?= $escape($domain['count']) ?></div><?php endforeach; ?></details></td>
<td><?php if ($kind === 'agents'): ?>
<select class="form-select" data-hdn-inventory-field aria-label="Destination list for <?= $escape($row['value']) ?>">
<?php foreach ($analysis['categories'] as $field => $title): ?>
<option value="<?= $escape($field) ?>" <?= $row['category'] === $field ? 'selected' : '' ?>><?= $escape($title) ?></option>
<?php endforeach; ?></select>
<?php else: ?><span>Selected PHP files</span><input type="hidden" data-hdn-inventory-field value="bans-missing_files-list"><?php endif; ?>
<?php if (empty($row['candidate'])): ?><small>Cannot append this value as a literal rule.</small><?php endif; ?></td>
</tr>
<?php endforeach; ?>
</tbody></table></div>
<?php if (empty($analysis['findings'])): ?><p class="u-mt10">No <?= $kind === 'agents' ? 'agent records' : 'PHP-path 404 records' ?> in the selected logs and time window.</p><?php endif; ?>
<?php if (($analysis['pages'] ?? 1) > 1): ?>
<nav class="hdn-ban-pager u-mt20" aria-label="Inventory pages">
<?php if ($analysis['page'] > 1): ?><button type="button" class="button button-secondary" data-hdn-analysis-page="<?= $analysis['page'] - 1 ?>">Previous</button><?php endif; ?>
<span>Page <?= $escape($analysis['page']) ?> of <?= $escape($analysis['pages']) ?></span>
<?php if ($analysis['page'] < $analysis['pages']): ?><button type="button" class="button button-secondary" data-hdn-analysis-page="<?= $analysis['page'] + 1 ?>">Next</button><?php endif; ?>
</nav><?php endif; ?>
<details class="u-mt20"><summary>Log coverage</summary>
<p><?= $escape($analysis['totals']['unparsed'] ?? 0) ?> malformed lines · <?= $escape($analysis['totals']['incomplete_lines'] ?? 0) ?> incomplete trailing lines skipped.</p>
<?php foreach ($analysis['unavailable_domains'] ?? [] as $domain): ?><p>No readable log: <?= $escape($domain) ?></p><?php endforeach; ?>
<?php foreach ($analysis['errors'] ?? [] as $row): ?><p><?= $escape($row['domain'] . ' · ' . $row['file'] . ': ' . $row['message']) ?></p><?php endforeach; ?>
<?php foreach ($analysis['coverage'] ?? [] as $row): ?><p><?= $escape($row['domain'] . ' · ' . $row['source'] . '/' . $row['file'] . ' · ' . $row['records'] . ' records · ' . $row['note']) ?></p><?php endforeach; ?>
</details>
<?php endif; ?>
</div>
