<?php if (!defined('SOFTACULOUS')) { http_response_code(403); exit; } ?>
<h2 class="u-mb20">WordPress administration access</h2>
<p class="u-mb20">Central defaults → account settings → domain settings. Each account can override the defaults for its own domains. Each domain can inherit or override its account.</p>
<p class="u-mb20">Choose an extra HTTP password or a simple local CAPTCHA for direct login/admin requests. Clients can imitate origin headers; WordPress authentication remains required. Customer account and checkout pages are outside this gate. AJAX, form handlers and password-strength scripts are exempt.</p>
<p class="u-mb20">Domain mode applies: <strong>Enforce</strong> activates protection, <strong>Observe</strong> records candidates without a prompt, and <strong>Off</strong> bypasses protection.</p>
<?php if ($isAdmin && isset($data['access_defaults'])):
    $entry = $data['access_defaults']; $profileAction = 'access_defaults_save'; $profileTarget = '';
    $profileGlobal = true; $profileLocked = false; $profileButton = 'Save central defaults'; ?>
<details class="box-collapse u-mb20" open>
    <summary class="box-collapse-header">Central defaults · all inheriting accounts and domains</summary>
    <div class="box-collapse-content"><?php require $install . '/panel/access-profile.php'; ?></div>
</details>
<?php endif; ?>
<div data-hdn-list="Account access profiles" data-hdn-columns='["Account / profile"]'>
<?php foreach ($data['access_accounts'] ?? [] as $accountName => $entry):
    $profileAction = 'access_account_save'; $profileTarget = $accountName;
    $profileGlobal = false; $profileLocked = false; $profileButton = 'Save account protection'; ?>
<details class="box-collapse u-mb20" data-hdn-list-row>
    <summary class="box-collapse-header">Account: <?= $escape($accountName) ?> · <?= !empty($entry['override']) ? 'Custom settings' : 'Inherits central defaults' ?></summary>
    <div class="box-collapse-content"><?php require $install . '/panel/access-profile.php'; ?></div>
</details>
<?php endforeach; ?>
</div><div data-hdn-list="Domain access profiles" data-hdn-columns='["Domain / profile"]'>
<?php foreach ($data['sites'] ?? [] as $site): if (($site['kind'] ?? 'web') === 'mail') continue;
    $entry = $data['access'][$site['key']]; $country = $entry['country'];
    $profileAction = 'access_save'; $profileTarget = $site['key']; $profileGlobal = false;
    $profileLocked = !$site['supported'] || $site['suspended']; $profileButton = 'Save domain protection'; ?>
<details class="box-collapse u-mb20" data-hdn-list-row>
    <summary class="box-collapse-header"><?= $escape($site['domain']) ?> · <?= $escape(ucfirst($site['mode'])) ?> · <?= !empty($entry['override']) ? 'Custom settings' : 'Inherits parent' ?> · <?= $entry['enabled'] ? (($entry['method'] ?? 'basic') === 'captcha' ? 'CAPTCHA' : 'HTTP password') : 'Access check off' ?> · Countries <?= $country['enabled'] ? 'enabled' : 'disabled' ?></summary>
    <div class="box-collapse-content"><?php require $install . '/panel/access-profile.php'; ?></div>
</details>
<?php endforeach; ?>

</div>
