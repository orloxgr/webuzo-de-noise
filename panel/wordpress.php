<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }

$wpStatus = $data['wordpress'] ?? [];
$wpSettings = $wpStatus['settings'] ?? ['enabled' => false, 'maxretry' => 3, 'findtime' => 300, 'durations' => [300, 259200, -1]];
$wpTimes = $wpSettings['durations'];
?>
<h2 class="u-mb20">WordPress login protection</h2>
<p class="u-mb20">Requires the <strong>WP fail2ban</strong> plugin to be installed and active in each WordPress site you want to protect.</p>
<p class="u-mb20">Its failed-login events must reach the server's authentication logs or journal with the visitor's real IP address. Configure logging permissions and trusted proxies for each site's hosting setup before enabling bans.</p>
<p class="u-mb20">Failed logins across all sites share the same IP counter. Bans apply to this server's websites on TCP 80/443, for IPv4 and IPv6.</p>
<form method="post">
<?php $fields('wordpress_save'); ?>
<label class="form-label u-block u-mb20" title="Enable or disable the WordPress authentication jail in the existing Fail2ban service."><input type="checkbox" name="wordpress_enabled" <?= !empty($wpSettings['enabled']) ? 'checked' : '' ?>> Enable WordPress login protection</label>
<h3 class="u-mb10">Failed attempts</h3>
<div class="hdn-wp-grid u-mb20">
<label class="form-label" title="Number of real authentication failures from one IP before its first ban. Fail2ban becomes stricter for repeat offenders.">Failures before first ban
<input class="form-control" name="wordpress_maxretry" type="number" min="1" value="<?= $escape($wpSettings['maxretry']) ?>" required></label>
<label class="form-label" title="Count failures that occur within this rolling time window, across all protected sites.">Counting window (minutes)
<input class="form-control" name="wordpress_window_minutes" type="number" min="1" value="<?= $escape($wpSettings['findtime'] / 60) ?>" required></label>
</div>
<h3 class="u-mb10">Ban escalation</h3>
<div class="hdn-wp-grid u-mb20">
<label class="form-label" title="How long the first ban lasts. The ban history is retained for repeat-offender escalation.">First ban
<input class="form-control" name="wordpress_first_minutes" type="number" min="1" value="<?= $escape($wpTimes[0] / 60) ?>" required></label>
<label class="form-label" title="Duration of the next ban for an IP already recorded as a WordPress offender.">Second ban (days)
<input class="form-control" name="wordpress_second_days" type="number" min="1" value="<?= $escape($wpTimes[1] / 86400) ?>" required></label>
<label class="form-label" title="Duration of the third and later bans. Enter zero for a permanent ban, which remains until an administrator unbans the IP.">Third ban (days; 0 = permanent)
<input class="form-control" name="wordpress_third_days" type="number" min="0" value="<?= $escape($wpTimes[2] === -1 ? 0 : $wpTimes[2] / 86400) ?>" required></label>
</div>
<p class="u-mb20">With a first-ban threshold of 3, native Fail2ban escalation requires 2 failures after the first ban and 1 after the second.</p>
<button class="button u-mb20" type="submit" title="Validate the generated Fail2ban configuration and apply this WordPress jail.">Save &amp; Apply WordPress protection</button>
</form>
<h3 class="u-mb10">Status and bans</h3>
<div id="hdn-wordpress-status" data-hdn-remote-list="wordpress" data-loaded="<?= !empty($wpStatus['loaded']) ? 'true' : 'false' ?>">
<?php if (!empty($wpStatus['error'])): ?><div class="alert alert-danger u-mb20" role="alert"><pre style="white-space:pre-wrap;overflow-wrap:anywhere"><?= $escape($wpStatus['error']) ?></pre></div><?php endif; ?>
<?php if (!empty($wpStatus['loaded']) && !empty($wpStatus['available'])): ?>
<p class="u-mb20">Fail2ban jail: <strong><?= !empty($wpStatus['active']) ? 'Active' : 'Inactive' ?></strong> · Banned IPs: <?= $escape($wpStatus['pagination']['total'] ?? count($wpStatus['ips'] ?? [])) ?></p>
<?php endif; ?>
<form method="post" id="hdn-wordpress-refresh"><?php $fields('wordpress_status'); ?><button type="submit" class="button button-secondary u-mb20" title="Read the current WordPress jail and bans from Fail2ban. Status is read only when requested.">Refresh status</button></form>
<?php if (!empty($wpStatus['loaded'])): $wpPage = $wpStatus['pagination'] ?? ['page'=>1,'pages'=>1]; ?>
<?php $wpUrl = static fn($changes) => '?' . $escape(http_build_query(array_merge($listing, ['act'=>'webuzo-de-noise','tab'=>'fail2ban','wordpress_read'=>1],$changes))); ?>
<nav class="hdn-list-controls u-mb20">
<label>Show per page <select class="form-select" data-hdn-remote-size="wordpress"><?php foreach ([20,50,100,500,'all'] as $size): ?><option value="<?= $size ?>" <?= ($wpPage['per_page'] ?? 50) === $size ? 'selected' : '' ?>><?= $size === 'all' ? 'All' : $size ?></option><?php endforeach; ?></select></label>
<span>Page <?= $escape($wpPage['page']) ?> / <?= $escape($wpPage['pages']) ?></span>
<?php if ($wpPage['page'] > 1): ?><a class="button button-secondary" data-hdn-remote-page href="<?= $wpUrl(['wordpress_page'=>$wpPage['page']-1]) ?>">Previous</a><?php endif; ?>
<?php if ($wpPage['page'] < $wpPage['pages']): ?><a class="button button-secondary" data-hdn-remote-page href="<?= $wpUrl(['wordpress_page'=>$wpPage['page']+1]) ?>">Next</a><?php endif; ?>
<a class="button button-secondary" href="<?= $wpUrl(['download_list'=>'wordpress']) ?>">Download CSV</a>
</nav><?php endif; ?>
<?php if (!empty($wpStatus['ips'])): ?>
<form method="post"><?php $fields('wordpress_unban'); ?>
<?php foreach ($wpStatus['ips'] as $address): ?><label class="form-label u-block u-mb10"><input type="checkbox" name="wordpress_ips[]" value="<?= $escape($address) ?>"> <?= $escape($address) ?></label><?php endforeach; ?>
<button class="button button-secondary" type="submit" title="Remove the selected IPs from this WordPress jail and its repeat-offender history.">Unban selected</button>
<button class="button button-secondary" type="submit" name="wordpress_unban_all" value="1" title="Remove every currently banned IP from the WordPress jail.">Unban all WordPress IPs</button>
</form>
<?php endif; ?>
</div>
<?php unset($wpStatus, $wpSettings, $wpTimes); ?>
