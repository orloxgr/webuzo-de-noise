<?php if (!defined('SOFTACULOUS') || !isset($data, $escape)) { http_response_code(403); exit; }
$endpointAnalysis = $data['analysis'] ?? null;
?>
<div id="hdn-endpoints-output">
<?php if (is_array($endpointAnalysis) && ($endpointAnalysis['inventory_kind'] ?? '') === 'endpoints'): $analysis = $endpointAnalysis; ?>
<h4 class="u-mt20">Endpoint suggestions · <?= $escape($analysis['minutes']) ?> minutes</h4>
<p><?= $escape($analysis['totals']['requests'] ?? 0) ?> native log records · <?= $escape($analysis['findings_total']) ?> domain/path findings · <?= $escape(round($analysis['bytes_read']/1048576, 2)) ?> MiB read.</p>
<p><?= !empty($analysis['partial']) ? 'Incomplete coverage; see coverage below.' : 'All available retained logs processed.' ?> <?= $escape($analysis['note']) ?></p>
<?php if (($analysis['endpoint_scope'] ?? '') !== 'all-non-image-paths'): ?><p>This older saved review covered backup/secret paths only. Run Analyze endpoint logs again to include JavaScript, CSS, PHP and other routes.</p><?php endif; ?>
<?php require __DIR__ . '/review-filters.php'; ?>
<?php if (!empty($analysis['suggestions'])): ?>
<h4 class="u-mt20">Grouped findings and advice</h4>
<div data-hdn-list="Endpoint suggestions">
<?php foreach ($analysis['suggestions'] as $proposal): ?>
<details class="hdn-endpoint-card" data-hdn-list-row><summary><strong><?= $escape($proposal['domain']) ?></strong><span><?= $escape($proposal['category'].' — '.$proposal['title']) ?></span><small><?= $escape($proposal['count']) ?> hits</small></summary>
<div class="hdn-endpoint-card-body">
<p><?= $escape($proposal['detail']) ?></p>
<div class="hdn-endpoint-meta"><span>Domain: <strong><?= $escape($proposal['domain']) ?></strong></span><span><?= count($proposal['paths']) ?> observed paths</span><span>HTTP <?= $escape(json_encode($proposal['statuses'])) ?></span></div>
<?php if (!empty($proposal['paths'])): ?>
<label class="form-label hdn-endpoint-paths-label">Select exact paths
<select class="form-select hdn-endpoint-paths" data-hdn-finding-paths multiple size="<?= min(10,max(3,count($proposal['paths']))) ?>">
<?php foreach ($proposal['paths'] as $findingPath): ?><option value="<?= $escape($findingPath) ?>" data-hdn-has404="<?= in_array($findingPath,$proposal['missing_paths'],true) ? '1' : '0' ?>"><?= $escape($findingPath) ?><?= in_array($findingPath,$proposal['missing_paths'],true) ? ' · 404 observed' : '' ?></option><?php endforeach; ?>
</select><small class="hdn-select-help">Press CTRL to select/deselect</small></label>
<div class="hdn-endpoint-actions"><button type="button" class="button button-secondary" data-hdn-select-findings="all" title="Select every exact path in this group. This does not append or save a rule.">Select all</button><button type="button" class="button button-secondary" data-hdn-select-findings="none" title="Deselect every path in this group. Existing rules and lists stay unchanged.">Clear selection</button></div>
<div class="hdn-endpoint-actions">
<?php if (!empty($proposal['paths'])): ?>
<button type="button" class="button button-secondary" title="Adds one disabled exact 403 rule per selected path, scoped to this domain, with IP banning off. Once enabled and saved, a 403 rule also blocks existing files; it does not wait for a 404." data-hdn-endpoint-group="<?= $escape(json_encode($proposal['paths'])) ?>" data-hdn-endpoint-site="<?= $escape($proposal['site']) ?>" data-hdn-endpoint-name="<?= $escape($proposal['category']) ?>">Append selected as disabled 403 rules</button>
<?php endif; ?>
<?php if (!empty($proposal['missing_paths'])): ?><button type="button" class="button button-secondary" title="Adds the selected exact paths with recorded 404 responses to the 404-ban list. Keeps the current Enabled switch, attempt threshold, counting window, duration and domain selection. After Save &amp; Apply, an enabled list bans an IP after its configured 404 threshold; existing files keep normal routing. Review the list domains before saving." data-hdn-endpoint404-group="<?= $escape(json_encode($proposal['missing_paths'])) ?>" data-hdn-endpoint-site="<?= $escape($proposal['site']) ?>">Append selected 404 paths</button><?php endif; ?>
</div>
<p class="hdn-endpoint-help">Preparing a 403 rule leaves it disabled. Adding to an already enabled 404 list takes effect when you Save &amp; Apply.</p>
<?php endif; ?>
<details class="hdn-endpoint-observed"><summary title="Shows every exact URL path observed in this group. This does not change protection.">View all observed paths</summary><ul><?php foreach ($proposal['paths'] as $proposedPath): ?><li><code><?= $escape($proposedPath) ?></code></li><?php endforeach; ?></ul></details>
</div></details>
<?php endforeach; ?>
</div>
<?php endif; ?>
<?php $reviewPage = $analysis; require __DIR__ . '/review-pagination.php'; ?>
<div class="hdn-endpoint-actions u-mt10"><label><input type="checkbox" title="Selects all exact paths with recorded 404 responses on this results page, regardless of extension or recommendation." data-hdn-select-endpoint404> Select all 404 paths on this page</label>
<button type="button" class="button button-secondary" title="Adds only the checked paths with recorded 404 responses to the exact 404 list. Keeps its Enabled switch, attempt threshold, counting window, duration and domains. Review scope before Save &amp; Apply; an enabled list bans on the configured 404 threshold." data-hdn-append-endpoint404>Append selected paths to the 404 list</button></div>

<p>Append is available for every exact finding, independently of the recommendation. Any path with a recorded 404 can be added to the 404 list, including JS, CSS and PHP. Appending is your manual selection; the analysis does not label every 404 as malicious.</p>
<p id="hdn-endpoint-append-status" role="status"></p>
<?php foreach ($analysis['findings'] ?? [] as $row): ?>
<details class="u-mt10"><summary><?php if (!empty($row['can_append_404'])): ?><input type="checkbox" data-hdn-endpoint404-path="<?= $escape($row['candidate']) ?>" data-hdn-endpoint-site="<?= $escape($row['site']) ?>" aria-label="Select exact 404 path <?= $escape($row['path']) ?>"> <?php endif; ?><strong><?= $escape($row['domain']) ?></strong> · <code><?= $escape($row['path']) ?></code> · <?= $escape($row['count']) ?> hits<?= $row['successful'] ? ' · successful/redirected responses present' : '' ?></summary>
<p><?= $escape($row['category'] . ' — ' . $row['advice']) ?></p>
<p>HTTP statuses: <?= $escape(json_encode($row['statuses'])) ?> · Methods: <?= $escape(json_encode($row['methods'])) ?> · Distinct clients: <?= $escape($row['clients']) ?></p>
<p><?= $escape(gmdate('Y-m-d H:i:s',(int)$row['first'])) ?> – <?= $escape(gmdate('Y-m-d H:i:s',(int)$row['last'])) ?> UTC</p>
<table class="table" data-hdn-list="Endpoint agents"><thead><tr><th>Declared agent (unverified)</th><th>Hits</th></tr></thead><tbody><?php foreach ($row['agents'] as $agent => $hits): ?><tr><td><?= $escape($agent) ?></td><td><?= $escape($hits) ?></td></tr><?php endforeach; ?></tbody></table>
<?php if (!empty($row['can_append'])): ?><button type="button" class="button button-secondary u-mt10" title="Prepares a disabled exact 403 rule for this domain, with IP banning off. Enabling and saving it blocks this URL even if a file exists." data-hdn-append-endpoint="<?= $escape($row['candidate']) ?>" data-hdn-endpoint-site="<?= $escape($row['site']) ?>">Append disabled endpoint rule</button><?php endif; ?>
<?php if (!empty($row['can_append_404'])): ?><button type="button" class="button button-secondary u-mt10" title="Adds this exact path to the 404 list, preserving its Enabled switch, attempt threshold, counting window, duration and domains. After Save &amp; Apply, an enabled list bans after the configured number of real 404s; 200 and redirects do not count." data-hdn-endpoint404-group="<?= $escape(json_encode([$row['candidate']])) ?>" data-hdn-endpoint-site="<?= $escape($row['site']) ?>">Append path to 404 list</button><?php endif; ?>
<?php $reviewRow=$row; require __DIR__ . '/review-note-controls.php'; ?>
</details>
<?php endforeach; if (empty($analysis['findings'])): ?><p>No matching non-image URL paths in these logs and time window.</p><?php endif; ?>
<details class="u-mt20"><summary>Log coverage</summary>
<?php foreach ($analysis['unavailable_domains'] ?? [] as $host): ?><p>No readable log: <?= $escape($host) ?></p><?php endforeach; ?>
<?php foreach ($analysis['errors'] ?? [] as $errorRow): ?><p><?= $escape($errorRow['domain'] . ' · ' . $errorRow['file'] . ': ' . $errorRow['message']) ?></p><?php endforeach; ?>
<table class="table" data-hdn-list="Endpoint log coverage"><thead><tr><th>Domain / source / log</th><th>Records</th><th>Coverage</th></tr></thead><tbody><?php foreach ($analysis['coverage'] ?? [] as $coverage): ?><tr><td><?= $escape($coverage['domain'] . ' · ' . $coverage['source'] . '/' . $coverage['file']) ?></td><td><?= $escape($coverage['records']) ?></td><td><?= $escape($coverage['note']) ?></td></tr><?php endforeach; ?></tbody></table>
</details>
<?php endif; ?>
</div>
