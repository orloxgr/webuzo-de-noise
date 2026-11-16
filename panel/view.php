<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }

$tabs = $isAdmin ? ['general' => 'General', 'agents' => 'User-Agents', 'endpoints' => 'Endpoints',
    'filters' => 'Filtered URLs', 'static' => 'Static files', 'bans' => 'IP bans',
    'enumeration' => 'User enumeration', 'access' => 'WP access', 'countries' => 'Countries', 'cron' => 'Cron', 'fail2ban' => 'Fail2ban', 'activity' => 'Activity'] : ['access' => 'WP access', 'domains' => 'Domains', 'activity' => 'Activity'];
$activeTab = isset($tabs[$activeTab ?? '']) ? $activeTab : array_key_first($tabs);
?>
<script>document.title = 'De-Noise';</script>
<style><?php readfile($install . '/panel/ui.css'); ?></style>
<div class="toolbar" id="hdn-toolbar"><div class="toolbar-inner"><div class="toolbar-buttons">
    <a class="button button-secondary" href="index.php" title="Return to the Webuzo dashboard."><i class="fas fa-arrow-left icon-blue"></i>Back</a>
    <?php if ($isAdmin): ?>
    <form method="post"><?php $fields('sync'); ?><button class="button button-secondary" type="submit" title="Discover domains, reapply saved HTTP rules and reconcile automatic web bans. Unsaved edits are not saved.">Synchronize now</button></form>
    <form method="post"><?php $fields('disable'); ?><button class="button button-secondary" type="submit" title="Turn off De-Noise website rules for all domains and disable its WordPress login jail. Website bans are released during maintenance. Service jails keep their own settings.">Disable website protection</button></form>
    <?php endif; ?>
</div></div></div>
<div class="container" id="hdn-container"><div class="form-container form-container-wide">
<h1 class="u-mb20">De-Noise</h1>
<?php if ($error !== ''): ?><div id="hdn-request-error" class="alert alert-danger u-mb20" role="alert"><pre style="white-space:pre-wrap;overflow-wrap:anywhere"><?= $escape($isAdmin ? $error : 'De-Noise is temporarily unavailable. Contact the administrator.') ?></pre></div>
<?php elseif ($message !== ''): ?><div class="alert alert-success u-mb20" role="status"><p><?= $escape($message) ?></p></div><?php endif; ?>
<?php if ($isAdmin && $error === '' && !empty($data['bans']['error'])): ?><div class="alert alert-danger u-mb20" role="alert"><p>Automatic web bans need attention:</p><pre style="white-space:pre-wrap;overflow-wrap:anywhere"><?= $escape($data['bans']['error']) ?></pre></div><?php endif; ?>
<?php if ($isAdmin && (!empty($data['maintenance']['error']) || !empty($data['maintenance']['stale']))): ?>
<div class="alert alert-danger u-mb20" role="alert"><p>Automatic maintenance needs attention.<?= !empty($data['maintenance']['stale']) ? ' No successful run in the last 3 minutes.' : '' ?></p><pre style="white-space:pre-wrap;overflow-wrap:anywhere"><?= $escape($data['maintenance']['error'] ?? '') ?></pre></div>
<?php endif; ?>
<?php if ($isAdmin): ?><form method="post" id="hdn-settings"><?php $fields('save'); ?></form><?php endif; ?>
<div class="tabs<?= $isAdmin ? ' hdn-admin-tabs' : '' ?>" id="hdn-tabs">
<div class="tabs-items" role="tablist" aria-label="De-Noise sections" style="--hdn-tab-columns:<?= (int)ceil(count($tabs) / 2) ?>">
<?php foreach ($tabs as $key => $label): ?>
<button type="button" class="tabs-item" id="hdn-tab-<?= $key ?>" data-hdn-tab="<?= $key ?>" role="tab" tabindex="<?= $key === $activeTab ? '0' : '-1' ?>" aria-selected="<?= $key === $activeTab ? 'true' : 'false' ?>" aria-controls="hdn-panel-<?= $key ?>"><?= $escape($label) ?></button>
<?php endforeach; ?></div>
<?php foreach ($tabs as $key => $label): ?>
<div class="tabs-panel" id="hdn-panel-<?= $key ?>" role="tabpanel" aria-labelledby="hdn-tab-<?= $key ?>" tabindex="0" <?= $key !== $activeTab ? 'hidden' : '' ?>>
<?php if ($key === 'general'): ?>
    <h2 class="u-mb20">Server defaults</h2>
    <label class="form-label" for="mode">Default mode</label>
    <select form="hdn-settings" class="form-select u-mb20" name="mode" id="mode">
        <?php foreach (['off' => 'Off', 'observe' => 'Observe — record matches, allow requests', 'enforce' => 'Enforce — block and rate-limit'] as $value => $name): ?>
        <option value="<?= $value ?>" <?= ($policy['mode'] ?? '') === $value ? 'selected' : '' ?>><?= $escape($name) ?></option>
        <?php endforeach; ?>
    </select>
    <label class="form-label u-block u-mb10"><input form="hdn-settings" type="checkbox" name="scanners" <?= !empty($policy['scanners']) ? 'checked' : '' ?>> Private-file protection</label>
    <p>Environment files, source-control metadata, configuration backups, cloud credentials and operating-system secret paths.</p>
    <label class="form-label u-block u-mt20"><input form="hdn-settings" type="checkbox" name="mail_protection" <?= !empty($policy['mail_protection']) ? 'checked' : '' ?> title="Apply the User-Agent lists and private-file protection to the native panel /mail/ route. SMTP, IMAP and other panel pages keep their existing behavior."> Protect webmail HTTP</label>
    <label class="form-label u-block u-mt20"><input form="hdn-settings" type="checkbox" name="log_rejections" <?= !empty($policy['log_rejections']) ? 'checked' : '' ?> title="Also record expected rate-limit rejections at error level in domain error logs. When off, they use notice level; Activity still records matches and genuine errors keep normal logging."> Detailed rate-limit messages in error logs</label>
    <button form="hdn-settings" id="hdn-general-save" class="button u-mt20 u-mb20" type="submit"><i class="fas fa-floppy-disk icon-purple"></i>Save &amp; Apply</button>
    <?php require $install . '/panel/domains.php'; ?>
<?php elseif ($key === 'agents'): ?>
    <?php require $install . '/panel/agent-lists.php'; ?>
    <?php $reviewKind = 'agents'; require $install . '/panel/inventory.php'; unset($reviewKind); ?>
<?php elseif ($key === 'endpoints'): ?>
    <?php require $install . '/panel/endpoints.php'; ?>
<?php elseif ($key === 'filters' || $key === 'static'): ?>
    <?php $ruleModule = $key; require $install . '/panel/rules.php'; unset($ruleModule); ?>
<?php elseif ($key === 'bans'): ?>
    <?php require $install . '/panel/bans.php'; ?>
<?php elseif ($key === 'fail2ban'): ?>
    <?php require $install . '/panel/fail2ban.php'; ?>
<?php elseif ($key === 'enumeration'): ?>
    <?php require $install . '/panel/enumeration.php'; ?>
<?php elseif ($key === 'access'): ?>
    <?php require $install . '/panel/access.php'; ?>
<?php elseif ($key === 'countries'): ?>
    <?php require $install . '/panel/countries.php'; ?>
<?php elseif ($key === 'cron'): ?>
    <?php require $install . '/panel/cron.php'; ?>
<?php elseif ($key === 'domains'): ?>
    <?php require $install . '/panel/domains.php'; ?>
<?php elseif ($key === 'activity'): ?>
    <?php require $install . '/panel/activity.php'; ?>
<?php endif; ?>
</div>
<?php endforeach; ?>
</div>
<?php if ($isAdmin): ?><button form="hdn-settings" id="hdn-save" class="button u-mt20" type="submit" <?= in_array($activeTab, ['general', 'cron', 'fail2ban', 'activity', 'access', 'countries'], true) ? 'hidden' : '' ?>><i class="fas fa-floppy-disk icon-purple"></i>Save &amp; Apply</button><?php endif; ?>
<p class="u-mt20"><small>Version <?= $escape($meta['version']) ?></small></p>
</div></div>
<?php require $install . '/panel/agent-presets.php'; ?>
<script type="application/json" id="hdn-probe-presets"><?= json_encode(['probe_files' => $data['presets']['probe_files'] ?? [], 'probe_queries' => $data['presets']['probe_queries'] ?? []], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
<script><?php readfile($install . '/panel/lists.js'); ?></script>
<script><?php readfile($install . '/panel/settings.js'); ?></script>
<?php if ($isAdmin): ?><script><?php readfile($install . '/panel/rules.js'); ?></script><script><?php readfile($install . '/panel/fail2ban.js'); ?></script><?php endif; ?>
