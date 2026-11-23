<?php if (!defined('SOFTACULOUS')) { http_response_code(403); exit; } ?>
<h2 class="u-mb20">User-Agent lists</h2>
<p class="u-mb10">Literal case-insensitive substrings. Priority across all categories: <strong>Individual rate limit &rarr; Group rate limit &rarr; Blocklist</strong>. Other protection rules still apply.</p>
<p class="u-mb20">Budgets are <strong>shared across all server websites and IPs</strong>. All matching requests count, including images, CSS and JavaScript. Each category has one shared group budget; each individual bot has its own budget and does not consume its group budget. Observe uses separate counters. Excess requests receive 429 in Enforce; no IP ban is created.</p>
<p class="u-mb20">These rate limits apply to hosted websites. Optional shared webmail protection keeps its separate User-Agent blocklists; website rate rules do not override those webmail blocks.</p>
<input form="hdn-settings" type="hidden" name="agent_limits_present" value="1">
<div class="hdn-agent-grid">
<?php foreach ($data['presets']['agent_categories'] ?? [] as $field => $category):
    $limits = $policy['agent_limits'][$field] ?? ['group'=>['enabled'=>false,'agents'=>[],'rate'=>null,'unit'=>'m','burst'=>0],'individual'=>[]];
?>
<details class="box-collapse hdn-agent-card" data-hdn-agent-category="<?= $escape($field) ?>">
<summary class="box-collapse-header"><?= $escape($category['title']) ?></summary>
<div class="box-collapse-content">
<p class="u-mb10"><?= $escape($category['description']) ?></p>
<div class="hdn-agent-columns">
<?php foreach (['block', 'rate'] as $destination):
    $isRate = $destination === 'rate'; $editor = $field . ($isRate ? '_rate' : '');
    $editorName = $isRate ? 'agent_groups[' . $field . '][agents]' : $field;
?>
<section class="hdn-agent-list">
<h3 class="u-mb10"><?= $isRate ? 'Group rate limit list' : 'Blocklist' ?></h3>
<label class="form-label u-block u-mb10"><input form="hdn-settings" type="checkbox" name="<?= $escape($isRate ? 'agent_groups[' . $field . '][enabled]' : $field . '_enabled') ?>" <?= ($isRate ? !empty($limits['group']['enabled']) : (!array_key_exists($field . '_enabled', $policy) || $policy[$field . '_enabled'])) ? 'checked' : '' ?> title="<?= $isRate ? 'Enable one shared budget for every agent in this group, excluding individual matches.' : 'Block these agents unless an enabled individual or group rate limit matches.' ?>"> Enable <?= $isRate ? 'group rate limit' : 'blocklist' ?></label>
<label class="form-label" for="<?= $escape($editor) ?>"><?= $escape($category['title']) ?> <?= $isRate ? 'group rate list' : 'blocklist' ?></label>
<textarea form="hdn-settings" class="form-control u-mb10" rows="6" id="<?= $escape($editor) ?>" name="<?= $escape($editorName) ?>" spellcheck="false"><?= $escape(implode("\n", $isRate ? $limits['group']['agents'] : ($policy[$field] ?? []))) ?></textarea>
<?php if ($isRate): ?><div class="hdn-agent-budget">
<label class="form-label">Requests<input form="hdn-settings" class="form-control" type="number" min="1" step="1" name="agent_groups[<?= $escape($field) ?>][rate]" value="<?= $escape($limits['group']['rate'] ?? '') ?>" title="Positive average rate shared by all bots in this group across every server website and IP. Required when enabled."></label>
<label class="form-label">Per<select form="hdn-settings" class="form-select" name="agent_groups[<?= $escape($field) ?>][unit]"><option value="m" <?= $limits['group']['unit'] === 'm' ? 'selected' : '' ?>>minute</option><option value="s" <?= $limits['group']['unit'] === 's' ? 'selected' : '' ?>>second</option></select></label>
<label class="form-label">Burst<input form="hdn-settings" class="form-control" type="number" min="0" step="1" required name="agent_groups[<?= $escape($field) ?>][burst]" value="<?= $escape($limits['group']['burst']) ?>" title="Extra requests allowed in a short burst without queuing. Zero allows no extra burst."></label>
</div><p class="u-mb10"><small>Shared across all server websites and IPs. A busy site can consume the group's budget for every site.</small></p><?php endif; ?>
<div class="hdn-inventory-actions">
<?php $appendPresets = $field === 'search_agents' ? ['search_additional'=>'Add additional search bots','search_major'=>'Add major search & AI bots'] :
    ($field === 'agents' ? ['data_collection'=>'Add Data Collection', 'monitoring'=>'Add Monitoring'] : [$field=>'Add suggested agents']);
foreach ($appendPresets as $preset => $caption): ?>
<button type="button" class="button button-secondary" data-hdn-preset="<?= $escape($preset) ?>" data-hdn-agent-field="<?= $escape($editor) ?>" title="Append optional names to this <?= $isRate ? 'group rate list' : 'blocklist' ?>. <?= $field === 'search_agents' ? 'Search restrictions can reduce visibility. ' : '' ?>Review before Save &amp; Apply; this button does not save or enable settings."><?= $escape($caption) ?></button>
<?php endforeach; ?>
<?php if ($field === 'agents'): ?>
<button type="button" class="button button-secondary" data-hdn-various-toggle aria-expanded="false" aria-controls="hdn-various-<?= $escape($editor) ?>" title="Choose generic automation or unconfirmed names individually for this <?= $isRate ? 'group rate list' : 'blocklist' ?>. Nothing is selected, saved or enabled automatically.">Add Various&hellip;</button>
<?php endif; ?>
<button type="button" class="button button-secondary" data-hdn-append-analyzed="<?= $escape($field) ?>" data-hdn-agent-field="<?= $escape($editor) ?>" aria-describedby="hdn-analyzed-<?= $escape($editor) ?>" disabled title="Append recognized names from the latest completed analysis, across all pages, to this <?= $isRate ? 'group rate list' : 'blocklist' ?>. Preserve current edits; do not save or enable settings.">Append analyzed agents</button>
</div>
<?php if ($field === 'agents') require $install . '/panel/agent-various.php'; ?>
<p class="u-mt10" id="hdn-analyzed-<?= $escape($editor) ?>" role="status">Uses the latest completed agent analysis, across all result pages.</p>
<?php if ($field === 'agents' || $field === 'tool_agents'): ?><p class="u-mt10"><small>Append analyzed agents includes recognized generic or unconfirmed names when present in the report. Review each name first; selected rows and manual editing remain available.</small></p><?php endif; ?>
</section>
<?php endforeach; ?>
</div>
<section class="hdn-agent-individual u-mt20">
<h3 class="u-mb10">Individual rate limit rules</h3>
<p class="u-mb10">Each enabled rule overrides every matching group limit and blocklist. Budgets are shared across all server websites and IPs. The longest individual substring wins; group matches use the same longest-substring order.</p>
<div class="hdn-agent-table-scroll"><table class="table hdn-agent-rates"><thead><tr><th>Enabled</th><th>Bot / User-Agent substring</th><th>Requests</th><th>Per</th><th>Burst</th><th>Actions</th></tr></thead><tbody data-hdn-agent-rate-body>
<?php foreach ($limits['individual'] as $rowIndex => $rule) require $install . '/panel/agent-rate-row.php'; ?>
</tbody></table></div>
<button type="button" class="button button-secondary u-mt10" data-hdn-agent-add title="Add an inactive individual rule with an empty name and rate. Fill in the bot and budget, enable deliberately, then Save &amp; Apply.">Add individual rule</button>
<template data-hdn-agent-rate-template><?php $rowIndex = '__INDEX__'; $rule = []; require $install . '/panel/agent-rate-row.php'; ?></template>
</section>
<details class="u-mt20 hdn-agent-preview"><summary title="Preview the effective User-Agent action for each configured name, including unsaved edits. Other security rules remain independent.">Effective actions for configured names</summary>
<p class="u-mt10" data-hdn-agent-conflicts role="status"></p>
<div class="hdn-agent-table-scroll"><table class="table"><thead><tr><th>Configured name</th><th>Effective User-Agent action</th></tr></thead><tbody data-hdn-agent-effective></tbody></table></div>
</details>
<?php if ($field === 'agents'): ?><p class="u-mt10">Recognized fetch clients and unconfirmed declarations remain available for individual review. Generic clients such as Go-http-client and quic-go are also used by legitimate integrations. Unknown agents remain selectable in analysis results.</p><?php endif; ?>
</div></details>
<?php endforeach; ?>
</div>
<p class="u-mt10">Categories describe purposes, not maliciousness. Appending preserves existing entries and switches and requires Save &amp; Apply. To limit selected URLs only, use Filtered URLs; those independent rules still apply.</p>
