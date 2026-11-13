<?php if (!defined('SOFTACULOUS')) { http_response_code(403); exit; } ?>
<?php $country = $entry['country']; ?>
<form method="post" autocomplete="off" class="hdn-access-form"><?php $fields($profileAction); ?>
    <input type="hidden" name="access_target" value="<?= $escape($profileTarget) ?>">
    <?php if (!$profileGlobal): ?>
    <p class="u-mb10">Effective profile: <strong><?= $escape(ucfirst($entry['source'] ?? 'global')) ?></strong>. Parent changes apply while this profile inherits.</p>
    <label class="form-label">Settings source
    <select class="form-select u-mb20" name="access_source" data-hdn-access-source <?= $profileLocked ? 'disabled' : '' ?> title="Inherit the parent profile, or override it here. An override can disable protection. Domain overrides take precedence over account settings.">
        <option value="inherit" <?= empty($entry['override']) ? 'selected' : '' ?>>Inherit parent settings</option>
        <option value="custom" <?= !empty($entry['override']) ? 'selected' : '' ?>>Custom settings (override)</option>
    </select></label>
    <?php endif; ?>
    <fieldset data-hdn-access-controls <?= $profileLocked || (!$profileGlobal && empty($entry['override'])) ? 'disabled' : '' ?>>
        <label class="form-label">Protection method
        <select class="form-select u-mb20" name="access_method" data-hdn-access-method title="Choose one additional administration check: Off, HTTP username/password, or a local image math CAPTCHA. Frontend handler exceptions and inheritance are shared.">
            <option value="off" <?= !$entry['enabled'] ? 'selected' : '' ?>>Off</option>
            <option value="basic" <?= $entry['enabled'] && ($entry['method'] ?? 'basic') === 'basic' ? 'selected' : '' ?>>HTTP username / password</option>
            <option value="captcha" <?= $entry['enabled'] && ($entry['method'] ?? 'basic') === 'captcha' ? 'selected' : '' ?>>CAPTCHA</option>
        </select></label>
        <label class="form-label u-block u-mb10" title="Bypass the extra access check for Sec-Fetch-Site: same-origin. Only when that header is absent, accept a Referer with the exact same scheme, hostname and default port. Direct, cross-site, same-site-only and headerless requests still need the selected check."><input type="checkbox" name="access_bypass_internal" <?= $entry['bypass_internal'] ? 'checked' : '' ?>> Bypass for internal requests</label>
        <div data-hdn-captcha-controls <?= ($entry['method'] ?? 'basic') !== 'captcha' || !$entry['enabled'] ? 'hidden' : '' ?>>
            <label class="form-label">Remember verification · seconds
            <input class="form-control u-mb10" type="number" min="1" step="1" name="captcha_seconds" value="<?= $escape($entry['captcha_seconds'] ?? 21600) ?>" title="How long this browser can access protected administration URLs after solving the CAPTCHA. 21600 seconds is six hours. The signed cookie is specific to the website; no shared IP or account lockout." required></label>
            <p class="u-mb20">A simple local image sum, with no external scripts or WordPress request. Successful verification uses a host-only cookie. Failed answers do not create IP bans. Use HTTPS for secure transport.</p>
        </div>
        <div data-hdn-basic-controls <?= ($entry['method'] ?? 'basic') === 'captcha' || !$entry['enabled'] ? 'hidden' : '' ?>>
        <div class="hdn-access-grid">
        <label class="form-label">HTTP username <input class="form-control u-mb10" name="access_username" value="<?= $escape($entry['username']) ?>" autocomplete="off" required title="The extra HTTP username. This is separate from the WordPress account."></label>
        <label class="form-label">New HTTP password <input class="form-control u-mb10" type="password" name="access_password" autocomplete="new-password" title="Leave empty to keep the saved password, or select password inheritance to use the parent password. Only a salted password hash is retained; the current password is never displayed."></label>
        </div>
        <?php if (!$profileGlobal): ?>
        <label class="form-label u-block u-mb10" title="Use the current parent password, including future password changes. Entering a new password creates a custom password instead."><input type="checkbox" name="access_inherit_password" <?= !empty($entry['password_inherited']) ? 'checked' : '' ?>> Inherit HTTP password from parent</label>
        <?php endif; ?>
        <p class="u-mb20"><?= $entry['password_set'] ? 'An HTTP password is available. Its value is never displayed.' : 'No HTTP password available. Set one here or in the parent profile before enabling the gate.' ?></p>
        </div>
        <h3 class="u-mb10">Country filter</h3>
        <p class="u-mb10">Requires the server country database<?= empty($data['geography']['available']) ? ' (not downloaded yet; ask the administrator)' : '' ?>. Country rules also apply to requests that bypass the access check.</p>
        <label class="form-label u-block u-mb10" title="Enable a separate geographic access policy for domains using this profile. A rejection returns HTTP 403; it does not create a firewall ban."><input type="checkbox" name="country_enabled" <?= $country['enabled'] ? 'checked' : '' ?>> Enable country filter</label>
        <div class="hdn-access-grid">
        <label class="form-label">Apply to <select name="country_scope" class="form-select u-mb10" title="Administration protects the WordPress login/admin paths with frontend handler exceptions. Entire site includes shop customers, APIs and payment/webhook services; select it only intentionally. ACME certificate validation remains accessible.">
            <option value="admin" <?= $country['scope'] === 'admin' ? 'selected' : '' ?>>WordPress administration only</option>
            <option value="site" <?= $country['scope'] === 'site' ? 'selected' : '' ?>>Entire site</option>
        </select></label>
        <label class="form-label">Policy <select name="country_mode" class="form-select u-mb10" title="Block selected countries, or allow only selected countries. The unknown-country choice is applied separately.">
            <option value="deny" <?= $country['mode'] === 'deny' ? 'selected' : '' ?>>Block selected countries</option>
            <option value="allow" <?= $country['mode'] === 'allow' ? 'selected' : '' ?>>Allow only selected countries</option>
        </select></label>
        </div>
        <label class="form-label">Country codes <textarea class="form-control u-mb10" name="country_codes" rows="3" placeholder="GR&#10;CY" title="Two-letter country codes, one per line or separated by commas. For example GR for Greece and CY for Cyprus."><?= $escape(implode("\n", $country['countries'])) ?></textarea></label>
        <label class="form-label u-block u-mb20" title="Allow IPs with no known location, including local/private addresses. When unchecked, unknown locations are rejected within the selected scope."><input type="checkbox" name="country_allow_unknown" <?= $country['allow_unknown'] ? 'checked' : '' ?>> Allow unknown country</label>
    </fieldset>
    <button class="button" type="submit" <?= $profileLocked ? 'disabled' : '' ?> title="Save this level. Inheriting domains use the resulting settings; explicit domain overrides remain unchanged."><?= $escape($profileButton) ?></button>
</form>
