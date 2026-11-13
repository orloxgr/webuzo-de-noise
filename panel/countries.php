<?php if (!defined('SOFTACULOUS')) { http_response_code(403); exit; } ?>
<h2 class="u-mb20">Local country database</h2>
<p class="u-mb20">Country filtering uses a local GeoLite2 Country database compiled into native Nginx IPv4/IPv6 lookup tables. No WordPress code, extra Nginx module or external API call runs for a visitor. Set each domain's policy in <strong>WP access</strong>.</p>
<p class="u-mb20">GeoLite2 data created by <a href="https://www.maxmind.com" target="_blank" rel="noopener noreferrer">MaxMind</a>. A central MaxMind account and GeoLite2 download license key are required; domains do not need separate accounts or DNS changes. IP location is approximate and VPNs can change the reported country.</p>
<?php $geo = $data['geography'] ?? []; ?>
<p class="u-mb10">Database: <?= !empty($geo['available']) ? 'available' : 'not downloaded' ?><?= !empty($geo['updated']) ? ' · Updated ' . $escape(date('Y-m-d H:i:s T', (int)$geo['updated'])) : '' ?><?= isset($geo['networks']) ? ' · ' . $escape(number_format($geo['networks'])) . ' networks' : '' ?></p>
<?php if (!empty($geo['error'])): ?><div class="alert alert-danger u-mb20"><p><?= $escape($geo['error']) ?></p><p>The last successfully applied database is retained.</p></div><?php endif; ?>
<form method="post" autocomplete="off" class="hdn-access-form"><?php $fields('geoip_save'); ?>
    <label class="form-label">MaxMind account ID <input class="form-control u-mb10" name="geoip_account_id" inputmode="numeric" value="<?= $escape($geo['account_id'] ?? '') ?>" title="The central server account used to download GeoLite2 Country CSV data from MaxMind."></label>
    <label class="form-label">License key <input class="form-control u-mb10" type="password" name="geoip_license_key" autocomplete="new-password" title="Enter a new key, or leave empty to reuse the saved key. It is kept in a root-private server file and never returned to the browser."></label>
    <p class="u-mb10"><?= !empty($geo['configured']) ? 'Credentials are saved; an empty key field keeps the current key.' : 'No download credentials saved.' ?></p>
    <label class="form-label u-block u-mb20" title="While a country filter is enabled, check for a fresh database weekly during existing maintenance. A failed update keeps the working database and is retried the next day; the failure is shown here."><input type="checkbox" name="geoip_automatic" <?= ($geo['automatic'] ?? true) ? 'checked' : '' ?>> Automatically update the local database</label>
    <button class="button button-secondary" type="submit" title="Save credentials and the automatic-update switch without making a network request or changing domain policies.">Save download settings</button>
    <button class="button" name="action" value="geoip_update" type="submit" title="Download the full GeoLite2 Country CSV archive, compile it, validate Nginx and apply it to configured domains. No domains are enabled automatically.">Download &amp; apply country database</button>
</form>
