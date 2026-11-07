<?php
if (!defined('SOFTACULOUS') || empty($isAdmin)) { http_response_code(403); exit; }
$f2b = $data['fail2ban'] ?? [];
$f2bRules = $f2b['settings'] ?? [];
$installJob = $data['install_job'] ?? ['state' => 'idle'];
$installPlan = $data['install_plan'] ?? null;
$installing = in_array($installJob['state'], ['queued', 'running'], true);
?>
<section class="box-collapse u-mb20" id="hdn-wordpress-protection"><div class="box-collapse-content">
<?php if (!$installing && !empty($f2b['installed'])): ?>
<?php require $install . '/panel/wordpress.php'; ?>
<?php else: ?>
<h2 class="u-mb20">WordPress login protection</h2>
<p class="u-mb20"><?= $installing ? 'Waiting for Fail2ban installation to finish.' : 'Install Fail2ban below first. WordPress login protection also requires the WP fail2ban plugin to be installed manually in each WordPress site you want to protect.' ?></p>
<?php endif; ?>
</div></section>
<h2 class="u-mb20">Fail2ban</h2>
<p class="u-mb20">Protect server services from repeated failed logins. These settings work independently of website Observe / Enforce modes. Each ban affects only the protected service's listed TCP ports.</p>
<div id="hdn-fail2ban-status" data-loaded="<?= !empty($f2b['loaded']) ? 'true' : 'false' ?>" data-installing="<?= $installing ? 'true' : 'false' ?>">
<?php if ($installing): ?>
<p class="u-mb10"><strong>Installation:</strong> In progress · <strong>Service:</strong> Waiting for installation to finish</p>
<?php else: ?>
<p class="u-mb10"><strong>Installation:</strong> <?= !empty($f2b['installed']) ? 'Installed' : 'Not installed' ?>
<?php if (!empty($f2b['loaded']) && !empty($f2b['installed'])): ?> · <strong>Service:</strong> <?= !empty($f2b['running']) ? 'Running' : 'Not available' ?><?php endif; ?></p>
<?php if (!empty($f2b['error'])): ?><div class="alert alert-danger u-mb20"><pre class="hdn-diagnostic"><?= $escape($f2b['error']) ?></pre></div><?php endif; ?>
<?php endif; ?>
<form method="post" id="hdn-fail2ban-refresh"><?php $fields('fail2ban_status'); ?><button class="button button-secondary u-mb20" type="submit">Refresh service status</button></form>
<?php if ($installing): ?>
<p class="u-mb20">Package installation and service checks are in progress. Service status will refresh automatically when installation finishes.</p>
<?php elseif (empty($f2b['installed'])): ?>
<p class="u-mb20">Install Fail2ban from the authenticated Ubuntu or Debian repositories configured on this server. De-Noise does not add repositories. Other distributions require manual installation of their Fail2ban package.</p>
<p class="u-mb20">Installation adds Fail2ban and its required packages and enables its system service. Distribution defaults may already enable an SSH jail. Additional De-Noise protections stay off until you select and save them.</p>
<form method="post"><?php $fields('fail2ban_install_preview'); ?><button class="button button-secondary u-mb20" type="submit">Preview Fail2ban installation</button></form>
<?php if ($installPlan): ?>
<h3 class="u-mb10">Installation preview</h3>
<p class="u-mb10"><?= $escape($installPlan['os']) ?> · Fail2ban <?= $escape($installPlan['version']) ?></p>
<p class="u-mb10">The following package changes are proposed. No packages will be removed.</p>
<pre class="hdn-diagnostic u-mb20"><?= $escape($installPlan['changes']) ?></pre>
<form method="post"><?php $fields('fail2ban_install_start'); ?><input type="hidden" name="plan_token" value="<?= $escape($installPlan['token']) ?>"><button class="button u-mb20" type="submit">Install Fail2ban &amp; start service</button></form>
<?php endif; ?>
<?php elseif (!empty($f2b['loaded']) && empty($f2b['running'])): ?>
<form method="post"><?php $fields('fail2ban_start'); ?><p class="u-mb10">Starting the service activates its existing enabled jails. Its configuration is checked first.</p><button class="button u-mb20" type="submit">Enable &amp; start existing Fail2ban service</button></form>
<?php endif; ?>
<?php if (in_array($installJob['state'], ['queued', 'running', 'failed', 'complete'], true)): ?>
<div id="hdn-install-progress" class="alert <?= $installJob['state'] === 'failed' ? 'alert-danger' : 'alert-info' ?> u-mb20" role="status" data-state="<?= $escape($installJob['state']) ?>"><?= $escape($installJob['error'] ?? $installJob['message'] ?? 'Fail2ban installation is in progress. You can leave this page and return to check its status.') ?></div>
<form method="post" id="hdn-install-poll"><?php $fields('fail2ban_install_status'); ?><button class="button button-secondary u-mb20" type="submit">Check installation progress</button></form>
<?php endif; ?>
<?php if (!empty($f2b['conflicts'])): ?><div class="alert alert-warning u-mb20">Other protection is active: <?= $escape(implode(', ', $f2b['conflicts'])) ?>. Review its authentication protections before adding another jail for the same service. De-Noise leaves these tools enabled and unchanged.</div><?php endif; ?>
<?php if (!empty($f2b['active_jails'])): ?><p class="u-mb20"><strong>Existing active jails:</strong> <?= $escape(implode(', ', $f2b['active_jails'])) ?>. Jails created outside De-Noise are managed separately.</p><?php endif; ?>
<?php if (!$installing && !empty($f2b['services'])): ?>
<form method="post" id="hdn-services-settings"><?php $fields('fail2ban_save'); ?></form>
<div class="hdn-agent-grid">
<?php foreach ($f2b['services'] as $service => $serviceInfo): $rule = $f2bRules[$service]; $existing = $serviceInfo['existing'] ?? []; ?>
<section class="box-collapse hdn-agent-card"><div class="box-collapse-content">
<h3 class="u-mb10"><?= $escape($serviceInfo['title']) ?></h3>
<p class="u-mb10"><?= $escape(['ssh' => 'Count failed SSH authentication attempts. Login methods, password authentication, root access, keys and listening ports are unchanged.', 'imap' => 'Count failed mailbox authentication through Dovecot. Ordinary disconnects and TLS failures do not trigger this protection.', 'smtp' => 'Count failed SMTP authentication through Exim. Spam rejections and unknown recipients do not trigger this protection.', 'ftp' => 'Count failed FTP authentication through PureFTPd.'][ $service ]) ?></p>
<p class="u-mb10"><strong>Detected TCP ports:</strong> <?= $escape(implode(', ', $serviceInfo['ports'])) ?: 'Not detected' ?> · <strong>De-Noise jail:</strong> <?= !empty($serviceInfo['active']) ? 'Active' : 'Inactive' ?></p>
<?php if (!empty($serviceInfo['source'])): ?><p class="u-mb10"><strong>Log source:</strong> <code><?= $escape($serviceInfo['source']['logpath'] ?? $serviceInfo['source']['journalmatch']) ?></code></p><?php endif; ?>
<?php if ($existing): ?><div class="alert alert-info u-mb10">Existing protection: <?= $escape(implode(', ', $existing)) ?>. De-Noise will not create a duplicate. Configure this jail in its existing configuration.</div><?php endif; ?>
<?php if (!empty($serviceInfo['error'])): ?><p class="u-mb10"><?= $escape($serviceInfo['error']) ?></p><?php endif; ?>
<?php $blocked = (!$serviceInfo['ready'] || $existing) && empty($rule['enabled']); ?>
<label class="form-label u-block u-mb10"><input form="hdn-services-settings" type="checkbox" name="services[<?= $escape($service) ?>][enabled]" <?= !empty($rule['enabled']) ? 'checked' : '' ?> <?= $blocked ? 'disabled' : '' ?>> Enable <?= $escape($serviceInfo['title']) ?> protection</label>
<?php if ($blocked): ?>
<?php foreach (['maxretry', 'findtime', 'bantime'] as $setting): ?><input form="hdn-services-settings" type="hidden" name="services[<?= $escape($service) ?>][<?= $escape($setting) ?>]" value="<?= $escape($rule[$setting]) ?>"><?php endforeach; ?>
<textarea form="hdn-services-settings" hidden name="services[<?= $escape($service) ?>][ignore_ips]"><?= $escape(implode("\n", $rule['ignore_ips'])) ?></textarea>
<?php else: ?>
<div class="hdn-wp-grid u-mb10">
<?php foreach (['maxretry' => 'Failed attempts', 'findtime' => 'Counting window (seconds)', 'bantime' => 'Ban duration (seconds)'] as $setting => $label): ?>
<label class="form-label"><?= $escape($label) ?><input form="hdn-services-settings" class="form-control" type="number" min="1" name="services[<?= $escape($service) ?>][<?= $escape($setting) ?>]" value="<?= $escape($rule[$setting]) ?>" required></label>
<?php endforeach; ?></div>
<label class="form-label">Never-ban IPs / networks (one per line)<textarea form="hdn-services-settings" class="form-control u-mb10" rows="3" name="services[<?= $escape($service) ?>][ignore_ips]" spellcheck="false"><?= $escape(implode("\n", $rule['ignore_ips'])) ?></textarea></label>
<p class="u-mb10">Server addresses and inherited Fail2ban exclusions remain exempt.<?php if ($service === 'ssh'): ?> Add your administrator IP before enabling SSH protection.<?php endif; ?></p>
<?php endif; ?>
<?php if ($serviceInfo['ready']): ?><form method="post"><?php $fields('fail2ban_test'); ?><input type="hidden" name="service" value="<?= $escape($service) ?>"><button class="button button-secondary u-mb10" type="submit">Test filter against recent logs</button></form><?php endif; ?>
<?php $test = $data['filter_test'][$service] ?? $data['service_result']['tests'][$service] ?? null; if ($test): ?><p class="u-mb10" role="status">Filter test: <?= $escape($test['matches']) ?> matched out of <?= $escape($test['lines']) ?> sampled log lines. <?= $escape($test['note']) ?></p><?php endif; ?>
<?php if (!empty($serviceInfo['ips'])): ?>
<details><summary class="u-mb10">Banned IPs: <?= count($serviceInfo['ips']) ?></summary>
<form method="post"><?php $fields('fail2ban_unban'); ?><input type="hidden" name="service" value="<?= $escape($service) ?>">
<div class="hdn-service-ips u-mb10"><?php foreach ($serviceInfo['ips'] as $ip): ?><label class="form-label u-block"><input type="checkbox" name="service_ips[]" value="<?= $escape($ip) ?>"> <?= $escape($ip) ?></label><?php endforeach; ?></div>
<button class="button button-secondary" type="submit">Unban selected IPs</button></form></details>
<?php endif; ?>
</div></section>
<?php endforeach; ?></div>
<button form="hdn-services-settings" class="button u-mt20 u-mb20" type="submit">Save &amp; Apply service protection</button>
<p class="u-mb20">Enabled filters are tested against recent logs before saving. Configuration is validated and reloaded; a failed change restores the previous configuration. Service configuration files are unchanged. After changing service ports or log settings elsewhere, refresh status and Save &amp; Apply again.</p>
<?php endif; ?>
</div>
<?php unset($f2b, $f2bRules, $installJob, $installPlan, $installing); ?>
