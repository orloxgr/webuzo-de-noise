<?php
if (!defined('SOFTACULOUS') || !isset($data, $escape)) { http_response_code(403); exit; }
$xmlrpcBlock = $policy['xmlrpc_block'] ?? ['enabled' => false, 'targets' => []];
$xmlrpcSites = array_values(array_filter($data['sites'] ?? [], static fn($site) => ($site['kind'] ?? 'web') === 'web'));
$xmlrpcKnown = array_column($xmlrpcSites, 'key');
?>
<details class="box-collapse hdn-endpoint-section u-mb20" id="hdn-xmlrpc-block-box">
<summary class="box-collapse-header">Disable XML-RPC</summary>
<div class="box-collapse-content">
<input form="hdn-settings" type="hidden" name="xmlrpc_block_present" value="1">
<label class="form-label u-block u-mb10"><input form="hdn-settings" type="checkbox" name="xmlrpc_block_enabled" <?= $xmlrpcBlock['enabled'] ? 'checked' : '' ?>> Disable XML-RPC for the checked sites</label>
<p>In Enforce, Nginx returns 403 for XML-RPC requests before they reach WordPress, including installations in subfolders. Observe records matches without blocking; Off allows normal routing. This does not ban IP addresses.</p>
<p>Jetpack connections, external XML-RPC publishing and pingbacks stop working on the checked sites. Normal wp-admin access is unchanged. This is separate from the XML-RPC rate limit below.</p>
<p>Check the sites to protect, then Save &amp; Apply. No checked sites means no XML-RPC blocking. Aliases of each checked site are included.</p>
<div class="hdn-list-controls u-mt10 u-mb10">
<button type="button" class="button button-secondary" data-hdn-xmlrpc-select="all" title="Check every listed site across all pages. Save &amp; Apply is required.">Select all sites</button>
<button type="button" class="button button-secondary" data-hdn-xmlrpc-select="none" title="Uncheck every listed site across all pages. Save &amp; Apply is required.">Clear selection</button>
</div>
<table class="table" data-hdn-list="Disable XML-RPC sites" id="hdn-xmlrpc-block-sites">
<thead><tr><th>Select</th><th>Domain</th><th>Account</th></tr></thead><tbody>
<?php foreach ($xmlrpcSites as $site): ?>
<tr><td><input form="hdn-settings" type="checkbox" name="xmlrpc_block_targets[]" value="<?= $escape($site['key']) ?>" <?= in_array($site['key'], $xmlrpcBlock['targets'], true) ? 'checked' : '' ?> aria-label="Disable XML-RPC on <?= $escape($site['domain']) ?>"></td><td><?= $escape($site['domain']) ?></td><td><?= $escape($site['owner']) ?></td></tr>
<?php endforeach; foreach (array_diff($xmlrpcBlock['targets'], $xmlrpcKnown) as $xmlrpcOld): ?>
<tr><td><input form="hdn-settings" type="checkbox" name="xmlrpc_block_targets[]" value="<?= $escape($xmlrpcOld) ?>" checked aria-label="Retain XML-RPC selection for <?= $escape($xmlrpcOld) ?>"></td><td><?= $escape($xmlrpcOld) ?> (unavailable)</td><td></td></tr>
<?php endforeach; ?>
</tbody></table>
</div></details>
