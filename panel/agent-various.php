<?php
if (!defined('SOFTACULOUS') || !isset($data, $escape, $editor, $isRate)) { http_response_code(403); exit; }
?>
<div id="hdn-various-<?= $escape($editor) ?>" class="hdn-agent-various u-mt10" data-hdn-various-picker data-hdn-agent-field="<?= $escape($editor) ?>" hidden>
<h4 class="u-mb10">Choose Various names for this <?= $isRate ? 'group rate list' : 'blocklist' ?></h4>
<p class="u-mb10">Generic automation can also run legitimate tests, monitoring and integrations. Other names have an unconfirmed purpose or operator. No names are selected automatically. These choices do not prove maliciousness.</p>
<div class="hdn-various-choices" role="group" aria-label="Various names for <?= $isRate ? 'group rate limit' : 'blocking' ?>">
<?php foreach ($data['presets']['agent_various'] ?? [] as $choice): ?>
<div class="hdn-various-choice">
<label><input type="checkbox" data-hdn-various-name value="<?= $escape($choice['name']) ?>"> <strong><?= $escape($choice['name']) ?></strong></label>
<p><small><?= $escape($choice['kind']) ?> &middot; <?= $escape($choice['operator']) ?></small></p>
<p><?= $escape($choice['purpose']) ?></p>
<p><small><?= $escape($choice['usefulness']) ?></small></p>
<?php if (is_string($choice['url'] ?? null) && strpos($choice['url'], 'https://') === 0): ?><a href="<?= $escape($choice['url']) ?>" target="_blank" rel="noopener noreferrer">Source</a><?php endif; ?>
</div>
<?php endforeach; ?>
</div>
<div class="hdn-inventory-actions u-mt10">
<button type="button" class="button button-secondary" data-hdn-various-append disabled title="Append only checked names to this <?= $isRate ? 'group rate list' : 'blocklist' ?>, preserving current edits and switches. Review and Save &amp; Apply explicitly.">Append selected to <?= $isRate ? 'group rate list' : 'blocklist' ?></button>
<button type="button" class="button button-secondary" data-hdn-various-close title="Close this picker without changing your lists or clearing selections.">Close</button>
</div>
<p class="u-mt10" data-hdn-various-status role="status"></p>
</div>
