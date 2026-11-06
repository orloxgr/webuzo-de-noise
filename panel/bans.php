<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }
 $ban = $policy['bans'] ?? []; $banState = $data['bans'] ?? []; ?>
<h2 class="u-mb20">Automatic IP bans</h2>
<label class="form-label u-block u-mb20"><input form="hdn-settings" type="checkbox" name="bans_enabled" <?= !empty($ban['enabled']) ? 'checked' : '' ?>> Enable automatic server-wide web bans</label>
<p class="u-mb20">Selected probes are rejected immediately. Automatic IPv4 and IPv6 bans synchronize within about one minute and affect the websites managed by De-Noise. SSH, email and panel access remain available.</p>
<label class="form-label u-block u-mb10"><input form="hdn-settings" type="checkbox" name="bans_private_files" <?= !empty($ban['private_files']) ? 'checked' : '' ?>> Secret and configuration-file probes, including traversal to secret paths</label>
<label class="form-label u-block u-mb20"><input form="hdn-settings" type="checkbox" name="bans_repositories" <?= !empty($ban['repositories']) ? 'checked' : '' ?>> Source-control metadata probes (.git, .svn, .hg)</label>
<h3 class="u-mb10">Direct secret / repository probes</h3>
<?php foreach (['maxretry' => ['Matching requests before ban', 1, 1],
               'findtime' => ['Counting window (seconds)', 1, 300],
               'duration_days' => ['Ban duration (days; 0 = permanent), for existing and new bans', 0, 0]] as $key => [$label, $minimum, $default]): ?>
<div class="u-mb20"><label class="form-label" for="bans-<?= $key ?>"><?= $escape($label) ?></label>
<input form="hdn-settings" class="form-control" type="number" id="bans-<?= $key ?>" name="bans_<?= $key ?>" min="<?= $minimum ?>" value="<?= $escape($ban[$key] ?? $default) ?>" required></div>
<?php endforeach; ?>
<?php foreach (['missing_files' => ['Ban IPs that 404 any of these files X times', 'paths', 'Selected PHP file paths — one per line', 'probe_files'],
               'suspicious_queries' => ['Ban IPs that 404 suspicious queries X times', 'targets', 'Secret file targets in query values — one per line', 'probe_queries']] as $key => [$title, $field, $label, $preset]):
    $rule = $ban[$key] ?? []; ?>
<details class="box-collapse u-mb20" open>
<summary class="box-collapse-header"><?= $escape($title) ?></summary>
<div class="box-collapse-content">
<label class="form-label u-block u-mb10"><input form="hdn-settings" type="checkbox" name="bans_<?= $key ?>_enabled" <?= !empty($rule['enabled']) ? 'checked' : '' ?>> Enabled</label>
<?php foreach (['maxretry' => ['X — matching ' . ($key === 'missing_files' ? 'distinct file paths' : 'requests') . ' before ban', 1, 2],
               'findtime' => ['Counting window (seconds)', 1, 60],
               'duration_days' => ['Ban duration (days; 0 = permanent)', 0, 3]] as $setting => [$settingLabel, $minimum, $default]): ?>
<label class="form-label u-block u-mb10"><?= $escape($settingLabel) ?><input form="hdn-settings" class="form-control" type="number" name="bans_<?= $key ?>_<?= $setting ?>" min="<?= $minimum ?>" value="<?= $escape($rule[$setting] ?? $default) ?>" required></label>
<?php endforeach; ?>
<?php if ($key === 'suspicious_queries'): ?>
<label class="form-label" for="bans-query-parameters">Query parameter names — one per line</label>
<textarea form="hdn-settings" class="form-control u-mb10" id="bans-query-parameters" name="bans_suspicious_queries_parameters" rows="3" spellcheck="false"><?= $escape(implode("\n", $rule['parameters'] ?? [])) ?></textarea>
<?php endif; ?>
<label class="form-label" for="bans-<?= $key ?>-list"><?= $escape($label) ?></label>
<textarea form="hdn-settings" class="form-control u-mb10" id="bans-<?= $key ?>-list" name="bans_<?= $key ?>_list" rows="7" spellcheck="false"><?= $escape(implode("\n", $rule[$field] ?? [])) ?></textarea>
<button type="button" class="button button-secondary u-mb10" data-hdn-probe-preset="<?= $preset ?>" data-hdn-probe-field="bans-<?= $key ?>-list" title="Merge bundled suggestions into this list without removing custom entries or changing thresholds, exceptions or enabled switches. Review, then Save &amp; Apply."><?= $key === 'missing_files' ? 'Add suggested PHP files' : 'Add suggested query targets' ?></button>
<p><?= $key === 'missing_files'
    ? 'Only selected nonexistent PHP files are rejected with 404. Existing files retain normal routing. Count distinct paths per IP across all domains.'
    : 'Match selected parameter names and complete secret file arguments, traversal to listed targets or PHP filter resource arguments, including encoded forms. Reject matches with 404 and count requests per IP across domains. Search parameters, ordinary relative paths and parameter names alone do not match the suggested rules.' ?></p>
</div></details>
<?php endforeach; ?>
<?php $notFound = $ban['any_404'] ?? []; ?>
<h3 class="u-mb10">Ban IPs after repeated 404 responses</h3>
<label class="form-label u-block u-mb10"><input form="hdn-settings" type="checkbox" name="bans_any_404_enabled" <?= !empty($notFound['enabled']) ? 'checked' : '' ?>> Enable general 404 bans</label>
<?php foreach (['maxretry' => ['404 responses before ban', 1, 10],
               'findtime' => ['Counting window (seconds)', 1, 300],
               'duration_days' => ['Ban duration (days; 0 = permanent)', 0, 3]] as $setting => [$label, $minimum, $default]): ?>
<label class="form-label u-block u-mb10"><?= $escape($label) ?><input form="hdn-settings" class="form-control" type="number" name="bans_any_404_<?= $setting ?>" min="<?= $minimum ?>" value="<?= $escape($notFound[$setting] ?? $default) ?>" required></label>
<?php endforeach; ?>
<label class="form-label u-block u-mb10"><input form="hdn-settings" type="checkbox" name="bans_any_404_exclude_static" <?= !empty($notFound['exclude_static']) ? 'checked' : '' ?> title="Do not count missing images, CSS, JavaScript, source maps, fonts, media or PDF files toward the general 404 ban. Explicit security probes keep their own counter."> Exclude missing static assets from general 404 bans</label>
<label class="form-label u-block u-mb10">Minimum different URL paths
<input form="hdn-settings" class="form-control" type="number" name="bans_any_404_min_distinct_paths" min="1" value="<?= $escape($notFound['min_distinct_paths'] ?? 3) ?>" required title="Require this many different URL paths as well as the request threshold within the counting window. Query strings do not create different paths. Set 1 to allow repeated requests to one path."></label>
<p class="u-mb20">Both limits must be reached. Counts apply per IP across selected web domains. Other status codes do not count. Explicit security probes retain their separate stricter counters. Existing bans are preserved.</p>
<?php if (!empty($data['sites'])): ?>
<h3 class="u-mb10">Probe exceptions by domain</h3>
<label class="form-label" for="hdn-probe-domain">Domain</label>
<select class="form-select u-mb10" id="hdn-probe-domain">
<?php foreach ($data['sites'] as $site): ?><option value="<?= $escape($site['key']) ?>"><?= $escape($site['domain'] . ' · ' . $site['owner']) ?></option><?php endforeach; ?>
</select>
<?php foreach ($data['sites'] as $index => $site): ?>
<div data-hdn-probe-domain="<?= $escape($site['key']) ?>" <?= $index ? 'hidden' : '' ?>>
<?php foreach (['files' => 'Allowed PHP paths', 'queries' => 'Allowed query endpoints (for example a legitimate file manager)'] as $kind => $label): ?>
<label class="form-label u-block u-mb10"><?= $escape($label) ?> — one exact URL path per line
<textarea form="hdn-settings" class="form-control" name="probe_exceptions_<?= $kind ?>[<?= $escape($site['key']) ?>]" rows="3" spellcheck="false"><?= $escape(implode("\n", $policy['probe_exceptions'][$kind][$site['key']] ?? [])) ?></textarea></label>
<?php endforeach; ?></div>
<?php endforeach; ?>
<p class="u-mb20">Exceptions bypass only their selected probe category, including its ban counter. Other protection remains active. Save &amp; Apply saves every domain.</p>
<?php endif; ?>
<label class="form-label" for="bans-targets">Domains that can trigger a ban (empty selection means all)</label>
<select form="hdn-settings" class="form-select u-mb20" id="bans-targets" name="bans_targets[]" multiple size="4">
<?php foreach ($data['sites'] ?? [] as $site): ?>
<option value="<?= $escape($site['key']) ?>" <?= in_array($site['key'], $ban['targets'] ?? [], true) ? 'selected' : '' ?>><?= $escape($site['domain'] . ' · ' . $site['owner']) ?></option>
<?php endforeach; ?></select>
<label class="form-label" for="bans-ignore">Never ban — one IP address or CIDR network per line</label>
<textarea form="hdn-settings" class="form-control u-mb20" id="bans-ignore" name="bans_ignore_ips" rows="4" spellcheck="false"><?= $escape(implode("\n", $ban['ignore_ips'] ?? [])) ?></textarea>
<p class="u-mb20">Never-ban entries bypass automatic IP bans only. Unselected 404s count only when general 404 bans are enabled. Crawler limits and User-Agent blocks do not count as 404s. Observe/Off domains do not trigger bans. Web bans support IPv4 and IPv6.</p>
<h3 class="u-mb10">Ban status</h3>
<?php $maintenance = $data['maintenance'] ?? []; ?>
<p class="u-mb10">Last successful maintenance: <?= !empty($maintenance['last_success']) ? $escape(gmdate('Y-m-d H:i:s', (int)$maintenance['last_success']) . ' UTC') : 'Not recorded yet' ?></p>
<form method="post" class="u-mb20"><?php $fields('history_settings_save'); ?>
<label class="form-label" for="history-days">History retention (days)</label>
<input class="form-control u-mb10" id="history-days" name="history_days" type="number" min="1" required value="<?= $escape($data['history']['days'] ?? 30) ?>" title="Completed ban history is removed after this many days during maintenance. Completed review reports use the same retention and are cleaned when a new review starts. Active bans and active reviews remain available.">
<button class="button button-secondary" type="submit" title="Save retention and remove completed history older than this limit.">Save history retention</button>
</form>
<?php if (!empty($banState['error'])): ?><div class="alert alert-danger u-mb20" role="alert"><pre style="white-space:pre-wrap;overflow-wrap:anywhere"><?= $escape($banState['error']) ?></pre></div><?php endif; ?>
<p class="u-mb10">Active: <?= $escape($banState['active'] ?? 0) ?> · Pending: <?= $escape($banState['pending'] ?? 0) ?> · Last sync: <?= !empty($banState['last_sync']) ? $escape(gmdate('Y-m-d H:i:s', (int)$banState['last_sync']) . ' UTC') : 'Not synchronized yet' ?></p>
<?php $listState = $banState; $listPrefix = 'bans'; $listTab = 'bans'; require $install . '/panel/ban-pagination.php'; ?>
<?php if (!$historyView): ?><form method="post"><?php $fields('unban'); ?>
<div class="u-mb10"><button class="button button-secondary" type="submit">Unban selected</button>
<button class="button button-secondary" type="submit" name="unban_all" value="1">Unban all De-Noise IPs</button>
</div>
<?php endif; ?>
<div class="hdn-scoped-table-wrap"><table class="table"><thead><tr><?php if (!$historyView): ?><th>Select</th><?php endif; ?><th>IP</th><th>Source domain</th><th>Reason</th><th>Recorded (UTC)</th><th>Expiry</th><th><?= $historyView ? 'Ended (UTC)' : 'Status' ?></th></tr></thead><tbody>
<?php foreach ($banState['rows'] ?? [] as $row): ?><tr>
<?php if (!$historyView): ?><td><input type="checkbox" name="ips[]" value="<?= $escape($row['ip']) ?>" aria-label="Unban <?= $escape($row['ip']) ?>"></td><?php endif; ?>
<td><?= $escape($row['ip']) ?></td><td><?= $escape($row['domain']) ?></td><td><?= $escape($row['reason']) ?><?php require $install . '/panel/ban-details.php'; ?></td>
<td><?= $escape(gmdate('Y-m-d H:i:s', (int)$row['created'])) ?></td>
<td><?= $row['expires'] ? $escape(gmdate('Y-m-d H:i:s', (int)$row['expires']) . ' UTC') : 'Permanent' ?></td>
<td><?= $historyView ? $escape(gmdate('Y-m-d H:i:s', (int)$row['ended'])) : $escape($row['status']) ?><?php if ($row['error']): ?><br><?= $escape($row['error']) ?><?php endif; ?></td></tr><?php endforeach; ?>
</tbody></table></div>
<?php if (empty($banState['rows'])): ?><p><?= $historyView ? 'No completed ban history.' : 'No active or pending De-Noise bans.' ?></p><?php endif; ?>
<?php if (!$historyView): ?></form><?php endif; ?>
