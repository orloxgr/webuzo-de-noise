<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }
?>
<h2 class="u-mb20">WordPress user enumeration</h2>
<p class="u-mb20">Restrict public user discovery while keeping authenticated WordPress requests available. No account/domain request quota or automatic IP ban is added.</p>
<?php foreach ([
    'enabled' => ['Enable user-enumeration protection', 'Apply the selected protections to WordPress sites in scope. Off/Observe/Enforce domain modes still apply. Existing installations start with this off.'],
    'rest' => ['Protect public REST user lists and profiles', 'Protect /wp-json/wp/v2/users and numeric profiles, including the rest_route query form. WordPress verifies credentials; invented cookies or headers do not grant access. Other REST routes and /users/me retain their normal permissions.'],
    'author_ids' => ['Protect author-ID discovery', 'Prevent anonymous ?author=1-style discovery before WordPress redirects to the author slug. Does not disable login, password resets or published posts.'],
    'author_archives' => ['Also protect public author archive pages', 'Optional: deny anonymous author archive pages. This can remove author pages from search results and affect themes that link to them. Leave off if public author pages are needed.'],
] as $name => [$label, $help]): ?>
<label class="form-label u-block u-mb20"><input form="hdn-settings" type="checkbox" name="enumeration_<?= $name ?>" <?= !empty($policy['enumeration'][$name]) ? 'checked' : '' ?> title="<?= $escape($help) ?>"> <?= $escape($label) ?></label>
<?php endforeach; ?>
<label class="form-label" for="enumeration-targets">Domains <span title="An empty selection covers all supported WordPress sites. Select domains to restrict the scope. Their aliases share the setting. HTML/PHP sites without WordPress are skipped.">ⓘ</span></label>
<select form="hdn-settings" class="form-select u-mb20" name="enumeration_targets[]" id="enumeration-targets" multiple size="8" title="Empty means all supported WordPress sites; otherwise only the selected domains and aliases.">
<?php foreach ($data['sites'] ?? [] as $site): if (($site['kind'] ?? 'web') !== 'web') continue; ?>
<option value="<?= $escape($site['key']) ?>" <?= in_array($site['key'], $policy['enumeration']['targets'] ?? [], true) ? 'selected' : '' ?>><?= $escape($site['domain'] . ' · ' . $site['owner']) ?></option>
<?php endforeach; ?>
</select>
<p>Nginx rejects requests without WordPress credentials before PHP. Enforce also installs a small, owned WordPress MU plugin to verify requests that present credentials. Disable removes that file; existing plugins and wp-config.php are not edited. No additional WordPress plugin is required.</p>
<p class="u-mt10">Uses the standard WordPress document root and wp-content/mu-plugins directory. Custom content directories report an error instead of silently applying incomplete protection. Existing public names and names printed in articles are not rewritten.</p>
