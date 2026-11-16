<?php
if (!defined('SOFTACULOUS') || !isset($data, $escape)) { http_response_code(403); exit; }
$renderEndpoint = static function ($index, array $row) use ($data, $escape): void {
    $field = static fn($name) => $escape('custom_endpoints[' . $index . '][' . $name . ']');
    $seconds = $row['duration_seconds']; $unit = 'seconds'; $duration = $seconds;
    foreach (['days' => 86400, 'hours' => 3600, 'minutes' => 60] as $label => $factor) {
        if ($seconds % $factor === 0) { $unit = $label; $duration = intdiv($seconds, $factor); break; }
    }
?>
<div class="hdn-rule u-mb20" data-module="custom_endpoints" data-hdn-list-row>
<input form="hdn-settings" type="hidden" name="<?= $field('id') ?>" value="<?= $escape($row['id']) ?>">
<label class="form-label u-block">Rule name <input form="hdn-settings" class="form-control" name="<?= $field('name') ?>" value="<?= $escape($row['name']) ?>" required></label>
<label class="form-label u-block u-mt10"><input form="hdn-settings" type="checkbox" name="<?= $field('enabled') ?>" <?= $row['enabled'] ? 'checked' : '' ?>> Enabled</label>
<label class="form-label u-block">Match type <select form="hdn-settings" class="form-select" name="<?= $field('type') ?>">
<option value="exact" <?= $row['type'] === 'exact' ? 'selected' : '' ?>>Exact path</option><option value="regex" <?= $row['type'] === 'regex' ? 'selected' : '' ?>>PCRE regular expression</option></select></label>
<label class="form-label u-block u-mt10">Path / regex <input form="hdn-settings" class="form-control" name="<?= $field('pattern') ?>" value="<?= $escape($row['pattern']) ?>" placeholder="/bak.sql.gz or ^/bak\.sql\.(?:gz|zip|zst)$" required spellcheck="false"></label>
<label class="form-label u-block u-mt10">Domains (empty selection means all web domains)
<select form="hdn-settings" class="form-select" name="<?= $field('targets') ?>[]" multiple size="4">
<?php $known = []; foreach ($data['sites'] ?? [] as $site): if (($site['kind'] ?? 'web') !== 'web') continue; $known[] = $site['key']; ?>
<option value="<?= $escape($site['key']) ?>" <?= in_array($site['key'], $row['targets'], true) ? 'selected' : '' ?>><?= $escape($site['domain'] . ' · ' . $site['owner']) ?></option>
<?php endforeach; foreach (array_diff($row['targets'], $known) as $old): ?><option value="<?= $escape($old) ?>" selected><?= $escape($old) ?> (unavailable)</option><?php endforeach; ?>
</select><small class="hdn-select-help">Press CTRL to select/deselect</small></label>
<label class="form-label u-block u-mt10"><input form="hdn-settings" type="checkbox" name="<?= $field('also_ban') ?>" <?= $row['also_ban'] ? 'checked' : '' ?>> Also ban IP after the first matching request in Enforce</label>
<div class="hdn-wp-grid u-mt10"><label class="form-label">Ban duration (0 = permanent)
<input form="hdn-settings" class="form-control" type="number" min="0" name="<?= $field('duration') ?>" value="<?= $escape($duration) ?>" required></label>
<label class="form-label">Unit <select form="hdn-settings" class="form-select" name="<?= $field('duration_unit') ?>">
<?php foreach (['minutes','hours','days','seconds'] as $choice): ?><option value="<?= $choice ?>" <?= $unit === $choice ? 'selected' : '' ?>><?= ucfirst($choice) ?></option><?php endforeach; ?>
</select></label></div>
<button type="button" class="button button-secondary u-mt10" data-hdn-remove title="Removes this rule from the form. Save &amp; Apply to remove the saved protection.">Remove rule</button>
</div>
<?php }; ?>
<input form="hdn-settings" type="hidden" name="endpoint_settings_schema" value="13">
<?php require __DIR__ . '/xmlrpc-block.php'; ?>
<?php require __DIR__ . '/endpoint-404.php'; ?>
<details class="box-collapse hdn-endpoint-section u-mb20" id="hdn-custom-endpoints-box">
<summary class="box-collapse-header">Custom endpoint rules</summary>
<div class="box-collapse-content">
<p class="u-mb10">In Enforce, matching requests return 403 before reaching the application, including existing files. Observe records matches; Off does nothing. Matching uses the decoded URL path, without query strings. PCRE is case-sensitive unless you use (?i). Rules are evaluated in list order; the first match determines the optional ban.</p>
<p class="u-mb10">Also ban IP uses the Webuzo De-Noise website IP-ban backend for all websites on this server. Never-ban IPs, server addresses and native exclusions still apply. The automatic maintenance job applies the ban after reading the matching request. The checkbox works independently of the IP bans master switch.</p>
<p id="hdn-custom_endpoints-message" role="status" class="u-mb10"></p>
<div id="hdn-custom_endpoints-rows" data-hdn-list="Custom endpoints" data-hdn-rule-list data-hdn-columns='["ID","Path","Settings"]'>
<?php foreach ($policy['custom_endpoints'] ?? [] as $i => $row) $renderEndpoint($i, $row); ?>
</div>
<button type="button" class="button button-secondary" data-hdn-add="custom_endpoints" title="Adds an empty, disabled rule for manual configuration. It takes effect only after you enable it and Save &amp; Apply.">Add endpoint rule</button>
<template id="hdn-custom_endpoints-template"><?php $renderEndpoint('__INDEX__', ['id'=>'custom_endpoints_1','name'=>'','enabled'=>false,'type'=>'exact','pattern'=>'','targets'=>[],'also_ban'=>false,'duration_seconds'=>86400]); ?></template>
</div></details>
<details class="box-collapse hdn-endpoint-section u-mb20" id="hdn-endpoint-analysis-box" <?= (($data['analysis']['inventory_kind'] ?? '') === 'endpoints') ? 'open' : '' ?>>
<summary class="box-collapse-header">Analyze endpoint logs and suggestions</summary>
<div class="box-collapse-content">
<form method="post" id="hdn-endpoints-scan" data-hdn-context="<?= $escape(($actor ?? '') . ':all') ?>">
<?php $fields('endpoints_start'); ?>
<div class="hdn-wp-grid"><label class="form-label">Domain <select class="form-select" name="analysis_target"><option value="all">All web domains</option>
<?php foreach ($data['sites'] ?? [] as $site): if (($site['kind'] ?? 'web') !== 'web') continue; ?><option value="<?= $escape($site['key']) ?>"><?= $escape($site['domain'] . ' · ' . $site['owner']) ?></option><?php endforeach; ?>
</select></label><label class="form-label">Time window (minutes)<input class="form-control" type="number" min="1" name="analysis_minutes" value="1440" required></label></div>
<button type="submit" class="button button-secondary u-mt10" title="Reads retained access logs and prepares findings and suggestions. This does not enable protection, add rules or ban IPs.">Analyze endpoint logs</button>
<button type="button" id="hdn-endpoints-cancel" class="button button-secondary" title="Stops this log review. Protection settings and saved rules stay unchanged." hidden>Cancel analysis</button>
<p id="hdn-endpoints-progress" class="u-mt10" role="status"></p>
</form>
<p class="u-mt10">Read-only review of all retained URL paths except images: JavaScript, stylesheets, PHP, backups and application routes, with every response status. Suggestions distinguish potential filename probes, missing assets and normal requests. Analysis never activates a rule or ban.</p>
<?php require __DIR__ . '/endpoint-output.php'; ?>
</div></details>
<?php require __DIR__ . '/endpoint-rates.php'; ?>
