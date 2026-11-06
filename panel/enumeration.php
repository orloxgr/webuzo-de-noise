<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }
?>
<h2 class="u-mb20">WordPress user enumeration</h2>
<p class="u-mb20">Control how visitors who are not signed in can discover WordPress users and authors. These settings do not ban IP addresses or limit request counts.</p>
<p class="u-mb20"><strong>No manual WordPress plugin installation is needed for any of these options.</strong> De-Noise automatically manages one shared WordPress helper for the selected protections.</p>
<?php foreach ([
    'enabled' => ['Enable user-enumeration protection', 'Main switch for the three protections below. Choose the protections and domains, then Save & Apply. Enforce blocks matching public requests with HTTP 403; Observe records matches without blocking; Off disables protection for that domain.'],
    'rest' => ['Protect public REST user lists and profiles', 'Block anonymous access to the WordPress API user list and individual user profiles, for example /wp-json/wp/v2/users and /wp-json/wp/v2/users/1, including the rest_route query form. Requests with valid WordPress authentication keep their normal permissions. Other API routes, such as posts and pages, are not blocked by this option. Features that rely on publicly fetching these user profiles may be affected.'],
    'author_ids' => ['Protect author-ID discovery', 'Block public requests such as /?author=1 that can reveal an author slug through a redirect. Public author archive URLs remain available unless the next option is also enabled. Login, password resets and published posts keep working.'],
    'author_archives' => ['Also protect public author archive pages', 'Also block anonymous access to pages that list posts by an author, for example /author/name/. Visitors and search crawlers will receive HTTP 403 on those pages. Individual articles remain available. Leave this off if the site needs public author pages.'],
] as $name => [$label, $help]): ?>
<div class="u-mb20">
<label class="form-label u-block u-mb10"><input form="hdn-settings" type="checkbox" id="enumeration-<?= $name ?>" name="enumeration_<?= $name ?>" <?= !empty($policy['enumeration'][$name]) ? 'checked' : '' ?> aria-describedby="enumeration-<?= $name ?>-help"> <?= $escape($label) ?></label>
<p id="enumeration-<?= $name ?>-help"><?= $escape($help) ?></p>
</div>
<?php endforeach; ?>
<label class="form-label" for="enumeration-targets">Domains</label>
<select form="hdn-settings" class="form-select u-mb10" name="enumeration_targets[]" id="enumeration-targets" multiple size="8" aria-describedby="enumeration-targets-help">
<?php foreach ($data['sites'] ?? [] as $site): if (($site['kind'] ?? 'web') !== 'web') continue; ?>
<option value="<?= $escape($site['key']) ?>" <?= in_array($site['key'], $policy['enumeration']['targets'] ?? [], true) ? 'selected' : '' ?>><?= $escape($site['domain'] . ' · ' . $site['owner']) ?></option>
<?php endforeach; ?>
</select>
<p id="enumeration-targets-help" class="u-mb20">Leave the selection empty to cover all supported WordPress sites, or select specific domains. Their aliases share the setting. Sites without WordPress are skipped. Each domain still follows its own Off, Observe or Enforce mode.</p>
<h3 class="u-mb10">How WordPress setup works</h3>
<p class="u-mb10">For selected domains in <strong>Enforce</strong>, Save &amp; Apply automatically installs <strong>Webuzo De-Noise User Enumeration Guard</strong> as a <a href="https://developer.wordpress.org/advanced-administration/plugins/mu-plugins/" target="_blank" rel="noopener noreferrer">Must-Use (MU) plugin</a>. WordPress loads it automatically; no activation in wp-admin is needed. It appears under <strong>Plugins &gt; Must-Use</strong>.</p>
<p class="u-mb10">The helper checks WordPress authentication before allowing access to protected user information. Authenticated requests still follow the normal WordPress permissions.</p>
<p class="u-mb10">All three protections use this same helper. <strong>Observe</strong> records matches without installing the helper for that domain. To turn protection off, clear the main switch and Save &amp; Apply; De-Noise removes its helper when it is no longer needed by any protected domain using that WordPress installation.</p>
<details class="box-collapse u-mb20"><summary class="box-collapse-header">Installation details</summary><div class="box-collapse-content">
<p class="u-mb10">Managed file: <code>wp-content/mu-plugins/webuzo-de-noise-user-enumeration.php</code>. Existing WordPress plugins and <code>wp-config.php</code> are not edited. Custom WordPress content/MU plugin directories report an error and require separate integration.</p>
<p>These options do not need WP fail2ban. That plugin is required separately for the <strong>WordPress logins</strong> feature. Published author names already printed in articles are not hidden by user-enumeration protection.</p>
</div></details>
