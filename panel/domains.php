<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }
?>
<h2 class="u-mb20">Domains</h2>
<?php if ($isAdmin): ?>
<form method="post"><?php $fields('bulk'); ?>
<div class="toolbar-buttons u-mb20">
    <button class="button button-secondary" id="hdn-select" type="button">Select all</button>
    <select class="form-select" name="bulk_mode" aria-label="Mode for selected domains">
        <option value="inherit">Inherit server default</option><option value="off">Off</option><option value="observe">Observe</option><option value="enforce">Enforce</option>
    </select><button class="button" type="submit">Apply to selected</button>
</div>
<?php endif; ?>
<div data-hdn-list="Domains" data-hdn-columns='["Domain","Account","Mode","Template","Aliases"]'>
<?php foreach ($data['sites'] ?? [] as $site): ?>
<details class="box-collapse u-mb10" data-hdn-list-row data-hdn-csv="<?= $escape(json_encode([$site['domain'],$site['owner'],$site['mode'],$site['template'],$site['aliases']])) ?>">
    <summary class="box-collapse-header">
        <?php if ($isAdmin): ?><input class="hdn-target" type="checkbox" name="targets[]" value="<?= $escape($site['key']) ?>" aria-label="Select <?= $escape($site['domain']) ?>"><?php endif; ?>
        <?= $escape($site['domain']) ?> · <?= $escape($site['owner']) ?> · <?= $escape(!$site['supported'] ? 'Unsupported' : ($site['suspended'] ? 'Suspended' : ucfirst($site['mode']))) ?>
    </summary>
    <div class="box-collapse-content">
        <p class="u-mb10">Proxy template: <?= $escape($site['template']) ?></p>
        <p class="u-mb10">Domain setting: <?= $escape($site['override']) ?></p>
        <?php if ($site['aliases'] !== ''): ?><p class="u-mb10">Aliases: <?= $escape($site['aliases']) ?></p><?php endif; ?>
        <?php if ($site['reason'] !== ''): ?><p><?= $escape($isAdmin ? $site['reason'] : 'This template is not currently supported.') ?></p><?php endif; ?>
    </div>
</details>
<?php endforeach; ?></div>
<?php if ($isAdmin): ?></form><?php endif; ?>
<?php if (empty($data['sites'])): ?><p>No domains to display.</p><?php endif; ?>
