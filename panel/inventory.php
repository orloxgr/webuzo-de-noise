<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }
$prefix = 'hdn-' . $reviewKind;
$reviewLabel = $reviewKind === 'agents' ? 'Analyze current agents' : 'Analyze PHP 404s';
?>
<section class="hdn-inventory u-mt20 u-mb20" aria-label="<?= $escape($reviewLabel) ?>">
<h3 class="u-mb10"><?= $escape($reviewLabel) ?></h3>
<form method="post" id="<?= $prefix ?>-scan" data-hdn-context="<?= $escape($actor . ':all') ?>">
<?php $fields($reviewKind . '_start'); ?>
<div class="hdn-wp-grid">
<label class="form-label">Domain
<select class="form-select" name="analysis_target">
<option value="all">All web domains</option>
<?php foreach ($data['sites'] ?? [] as $site): if (($site['kind'] ?? 'web') !== 'web') continue; ?>
<option value="<?= $escape($site['key']) ?>"><?= $escape($site['domain'] . ' · ' . $site['owner']) ?></option>
<?php endforeach; ?>
</select></label>
<label class="form-label">Time window (minutes)
<input class="form-control" type="number" name="analysis_minutes" min="1" value="30" required></label>
</div>
<button type="submit" class="button button-secondary u-mt10"><?= $escape($reviewLabel) ?></button>
<button type="button" id="<?= $prefix ?>-cancel" class="button button-secondary" hidden>Cancel analysis</button>
<p id="<?= $prefix ?>-progress" class="u-mt10" role="status"></p>
</form>
<p class="u-mb10"><?= $reviewKind === 'agents' ? 'Hits per declared agent, including asset requests. Recognized names are grouped across versions. Image and rendering crawlers stay separate. Browser strings, application clients and unrecognized names can appear under Other; that category does not mean they should be blocked.' : 'Hits per PHP URL path that returned HTTP 404. Check the source domains before adding a path to the server-wide list; a 404 can also come from a legitimate application route.' ?></p>
<p class="u-mb10">Append adds selected entries to your unsaved lists. Review them, then Save &amp; Apply. Existing entries, enable switches and ban thresholds stay as you set them.</p>
<?php require $install . '/panel/inventory-output.php'; ?>
</section>
