<?php
if (!defined('SOFTACULOUS') || !isset($data, $escape)) { http_response_code(403); exit; }
$xmlrpcBlock = $policy['xmlrpc_block'] ?? ['enabled' => false, 'global' => false, 'targets' => [], 'global_exceptions' => [], 'exceptions' => []];
$xmlrpcExceptions = (array)($xmlrpcBlock['exceptions'] ?? []);
$xmlrpcSites = array_values(array_filter($data['sites'] ?? [], static fn($site) => ($site['kind'] ?? 'web') === 'web'));
$xmlrpcKnown = array_column($xmlrpcSites, 'key');
foreach (array_diff(array_unique(array_merge($xmlrpcBlock['targets'], array_keys($xmlrpcExceptions))), $xmlrpcKnown) as $xmlrpcOld) {
    $xmlrpcSites[] = ['key'=>$xmlrpcOld, 'domain'=>$xmlrpcOld.' (unavailable)', 'owner'=>''];
}
?>
<details class="box-collapse hdn-endpoint-section u-mb20" id="hdn-xmlrpc-block-box">
<summary class="box-collapse-header">Disable XML-RPC</summary>
<div class="box-collapse-content">
<input form="hdn-settings" type="hidden" name="xmlrpc_block_present" value="1">
<input form="hdn-settings" type="hidden" name="xmlrpc_exceptions_present" value="1">
<label class="form-label u-block u-mb10"><input form="hdn-settings" type="checkbox" name="xmlrpc_block_enabled" <?= $xmlrpcBlock['enabled'] ? 'checked' : '' ?>> Enable XML-RPC blocking</label>
<p>In Enforce, Nginx returns 403 for XML-RPC requests before they reach WordPress, including installations in subfolders. Observe records matches without blocking; Off allows normal routing. This does not ban IP addresses.</p>
<p>Check <strong>Global</strong> to cover every current and future site, or check individual sites below. Global has its own allowed IP list and <strong>Allow Jetpack</strong> button, just like each site. Apply changes with <strong>Save &amp; Apply</strong>.</p>
<p>Need Jetpack? Click <strong>Allow Jetpack</strong> in Global or beside a site. The button adds the current official IP ranges to that box and keeps your existing exceptions. Click it again to add newly published ranges; it does not update automatically.</p>
<p>With Global off and no checked sites, no XML-RPC blocking is applied. Global exceptions apply across protected sites when Global is checked; per-site exceptions add access only on that site and its aliases. Other rules, IP bans and the XML-RPC rate limit still apply. Normal wp-admin access is unchanged.</p>
<details class="hdn-xmlrpc-help u-mb10"><summary>Other services and manual IP exceptions</summary>
<p>For other XML-RPC clients, open Allowed IPs / CIDRs beside the site and enter IPv4/IPv6 addresses or CIDRs, one per line. Behind a proxy, Nginx must already obtain the real client IP from that trusted proxy.</p>
<p>Jetpack's <a href="https://jetpack.com/ips-v4.txt" target="_blank" rel="noopener noreferrer">official IP list</a> can change. See the <a href="https://jetpack.com/support/how-to-add-jetpack-ips-allowlist/" target="_blank" rel="noopener noreferrer">Jetpack instructions</a>.</p>
</details>
<div class="hdn-list-controls u-mt10 u-mb10">
<button type="button" class="button button-secondary" data-hdn-xmlrpc-select="all" title="Check every listed site across all pages. Save &amp; Apply is required.">Select all sites</button>
<button type="button" class="button button-secondary" data-hdn-xmlrpc-select="none" title="Uncheck every listed site across all pages. Save &amp; Apply is required.">Clear selection</button>
</div>
<table class="table" data-hdn-list="Disable XML-RPC sites" id="hdn-xmlrpc-block-sites">
<thead><tr><th>Select</th><th>Domain</th><th>Account</th><th>IP exceptions</th></tr></thead><tbody>
<tr class="hdn-xmlrpc-global"><td><input form="hdn-settings" type="checkbox" name="xmlrpc_block_global" <?= !empty($xmlrpcBlock['global']) ? 'checked' : '' ?> aria-label="Disable XML-RPC globally on all current and future sites"></td><td><strong>Global</strong><br><small>All current and future sites</small></td><td>All accounts</td><td class="hdn-xmlrpc-exceptions">
<button type="button" class="button button-secondary u-mb10" data-hdn-allow-jetpack title="Append the current official Jetpack IP ranges to the Global exceptions. Save &amp; Apply is required.">Allow Jetpack</button>
<small class="hdn-jetpack-status" data-hdn-jetpack-status role="status"></small>
<details <?= !empty($xmlrpcBlock['global_exceptions']) ? 'open' : '' ?>><summary title="Global XML-RPC source IP exceptions. Used when the Global checkbox is selected.">Allowed IPs / CIDRs</summary>
<textarea data-hdn-csv-value form="hdn-settings" class="form-control u-mt10" name="xmlrpc_block_global_exceptions" rows="4" spellcheck="false" aria-label="Global XML-RPC allowed IPs / CIDRs" placeholder="192.0.2.10&#10;2001:db8::/32"><?= $escape(implode("\n", $xmlrpcBlock['global_exceptions'] ?? [])) ?></textarea>
</details></td></tr>
<?php foreach ($xmlrpcSites as $site): ?>
<tr><td><input form="hdn-settings" type="checkbox" name="xmlrpc_block_targets[]" value="<?= $escape($site['key']) ?>" <?= in_array($site['key'], $xmlrpcBlock['targets'], true) ? 'checked' : '' ?> aria-label="Disable XML-RPC on <?= $escape($site['domain']) ?>"></td><td><?= $escape($site['domain']) ?></td><td><?= $escape($site['owner']) ?></td><td class="hdn-xmlrpc-exceptions">
<button type="button" class="button button-secondary u-mb10" data-hdn-allow-jetpack title="Download Jetpack's current official IP ranges and append them for this site. Existing IPs and switches are kept. Save &amp; Apply is required.">Allow Jetpack</button>
<small class="hdn-jetpack-status" data-hdn-jetpack-status role="status"></small>
<details <?= !empty($xmlrpcExceptions[$site['key']]) ? 'open' : '' ?>><summary title="Allow these source IPs to use XML-RPC on this site only. Save &amp; Apply is required.">Allowed IPs / CIDRs</summary>
<textarea data-hdn-csv-value form="hdn-settings" class="form-control u-mt10" name="xmlrpc_block_exceptions[<?= $escape($site['key']) ?>]" rows="4" spellcheck="false" aria-label="XML-RPC allowed IPs / CIDRs for <?= $escape($site['domain']) ?>" placeholder="192.0.2.10&#10;2001:db8::/32"><?= $escape(implode("\n", $xmlrpcExceptions[$site['key']] ?? [])) ?></textarea>
</details></td></tr>
<?php endforeach; ?>
</tbody></table>
</div></details>
