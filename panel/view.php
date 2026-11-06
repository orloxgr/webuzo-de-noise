<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }

$tabs = $isAdmin ? ['general' => 'General', 'agents' => 'User-Agents', 'endpoints' => 'Endpoints',
    'filters' => 'Filtered URLs', 'static' => 'Static files', 'bans' => 'IP bans', 'domain-bans' => 'Domain bans',
    'enumeration' => 'User enumeration', 'wordpress' => 'WordPress logins', 'cron' => 'Cron', 'domains' => 'Domains', 'activity' => 'Activity'] : ['domain-bans' => 'Domain bans', 'domains' => 'Domains', 'activity' => 'Activity'];
$activeTab = isset($tabs[$activeTab ?? '']) ? $activeTab : array_key_first($tabs);
?>
<script>document.title = 'De-Noise';</script>
<style><?php readfile($install . '/panel/ui.css'); ?></style>
<div class="toolbar" id="hdn-toolbar"><div class="toolbar-inner"><div class="toolbar-buttons">
    <a class="button button-secondary" href="index.php"><i class="fas fa-arrow-left icon-blue"></i>Back</a>
    <?php if ($isAdmin): ?>
    <form method="post"><?php $fields('sync'); ?><button class="button button-secondary" type="submit">Synchronize now</button></form>
    <form method="post"><?php $fields('disable'); ?><button class="button button-secondary" type="submit">Disable everywhere</button></form>
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
    <label class="form-label u-block u-mt20"><input form="hdn-settings" type="checkbox" name="allow_domain_bans" <?= !array_key_exists('domain_bans', $policy) || !empty($policy['domain_bans']['allow_users']) ? 'checked' : '' ?>> Allow domain owners to edit their additional domain-only automatic bans</label>
<?php elseif ($key === 'agents'): ?>
    <h2 class="u-mb20">User-Agent lists</h2>
    <p class="u-mb20">One literal substring per line. Case-insensitive. Each list has its own switch.</p>
    <div class="hdn-agent-grid">
    <?php foreach ($data['presets']['agent_categories'] ?? [] as $field => $category): $isOther = $field === 'agents'; ?>
    <<?= $isOther ? 'details' : 'section' ?> class="box-collapse hdn-agent-card<?= $isOther ? ' hdn-agent-other' : '' ?>">
    <?php if ($isOther): ?><summary class="box-collapse-header"><?= $escape($category['title']) ?></summary><?php endif; ?>
    <div class="box-collapse-content">
    <?php if (!$isOther): ?><h3 class="u-mb10"><?= $escape($category['title']) ?></h3><?php endif; ?>
    <p class="u-mb10"><?= $escape($category['description']) ?></p>
    <label class="form-label u-block u-mb10"><input form="hdn-settings" type="checkbox" name="<?= $field ?>_enabled" <?= !array_key_exists($field . '_enabled', $policy) || $policy[$field . '_enabled'] ? 'checked' : '' ?>> Enable this list</label>
    <label class="form-label" for="<?= $field ?>"><?= $escape($category['title']) ?> blocklist</label>
    <textarea form="hdn-settings" class="form-control u-mb10" rows="6" id="<?= $field ?>" name="<?= $field ?>" spellcheck="false"><?= $escape(implode("\n", $policy[$field] ?? [])) ?></textarea>
    <button type="button" class="button button-secondary" data-hdn-preset="<?= $field ?>" data-hdn-agent-field="<?= $field ?>">Add suggested agents</button>
    </div></<?= $isOther ? 'details' : 'section' ?>>
    <?php endforeach; ?>
    </div>
    <p class="u-mt10">Lists describe crawler purposes, not whether requests are malicious. Suggested entries are optional. To limit crawlers only on particular URLs, use Filtered URLs.</p>
    <?php $reviewKind = 'agents'; require $install . '/panel/inventory.php'; unset($reviewKind); ?>
<?php elseif ($key === 'endpoints'): ?>
    <h2 class="u-mb20">Endpoint rate limits</h2>
    <?php foreach (['login' => 'WordPress login — POST /wp-login.php', 'xmlrpc' => 'WordPress XML-RPC — POST /xmlrpc.php'] as $endpoint => $name): ?>
    <h3 class="u-mb10"><?= $escape($name) ?></h3>
    <label class="form-label u-block u-mb10"><input form="hdn-settings" type="checkbox" name="<?= $endpoint ?>_enabled" <?= !empty($policy[$endpoint]['enabled']) ? 'checked' : '' ?>> Enabled</label>
    <label class="form-label" for="<?= $endpoint ?>-rate">Requests per minute, per client and domain</label>
    <input form="hdn-settings" class="form-control u-mb10" id="<?= $endpoint ?>-rate" type="number" min="1" name="<?= $endpoint ?>_rate" value="<?= $escape($policy[$endpoint]['rate'] ?? 5) ?>" required>
    <label class="form-label" for="<?= $endpoint ?>-burst">Burst allowance</label>
    <input form="hdn-settings" class="form-control u-mb20" id="<?= $endpoint ?>-burst" type="number" min="0" name="<?= $endpoint ?>_burst" value="<?= $escape($policy[$endpoint]['burst'] ?? 3) ?>" required>
    <?php endforeach; ?>
<?php elseif ($key === 'filters' || $key === 'static'): ?>
    <?php $ruleModule = $key; require $install . '/panel/rules.php'; unset($ruleModule); ?>
<?php elseif ($key === 'bans'): ?>
    <?php require $install . '/panel/bans.php'; ?>
<?php elseif ($key === 'wordpress'): ?>
    <?php require $install . '/panel/wordpress.php'; ?>
<?php elseif ($key === 'enumeration'): ?>
    <?php require $install . '/panel/enumeration.php'; ?>
<?php elseif ($key === 'cron'): ?>
    <?php require $install . '/panel/cron.php'; ?>
<?php elseif ($key === 'domain-bans'): ?>
    <?php require $install . '/panel/domain-bans.php'; ?>
<?php elseif ($key === 'domains'): ?>
    <?php require $install . '/panel/domains.php'; ?>
<?php elseif ($key === 'activity'): ?>
    <?php require $install . '/panel/activity.php'; ?>
<?php endif; ?>
</div>
<?php endforeach; ?>
</div>
<?php if ($isAdmin): ?><button form="hdn-settings" id="hdn-save" class="button u-mt20" type="submit" <?= in_array($activeTab, ['cron', 'domain-bans', 'wordpress'], true) ? 'hidden' : '' ?>><i class="fas fa-floppy-disk icon-purple"></i>Save &amp; Apply</button><?php endif; ?>
<p class="u-mt20"><small>Version <?= $escape($meta['version']) ?></small></p>
</div></div>
<script type="application/json" id="hdn-agent-presets"><?= json_encode(array_map(static fn($category) => $category['entries'], $data['presets']['agent_categories'] ?? []), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
<script type="application/json" id="hdn-probe-presets"><?= json_encode(['probe_files' => $data['presets']['probe_files'] ?? [], 'probe_queries' => $data['presets']['probe_queries'] ?? []], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
<script><?php readfile($install . '/panel/settings.js'); ?></script>
<?php if ($isAdmin): ?><script><?php readfile($install . '/panel/rules.js'); ?></script><?php endif; ?>
