<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }
if (!isset($analysis['filters'])) return;
$chosen = $analysis['filters'];
?>
<div class="hdn-review-filters u-mt10 u-mb10" data-hdn-review-filters>
<div class="hdn-wp-grid">
<label class="form-label">Domain<select class="form-select" data-hdn-filter="domain">
<option value="all">All domains</option>
<?php foreach ($analysis['filter_domains'] ?? [] as $domain): ?><option value="<?= $escape($domain) ?>" <?= $chosen['domain'] === $domain ? 'selected' : '' ?>><?= $escape($domain) ?></option><?php endforeach; ?>
</select></label>
<label class="form-label">Review priority<select class="form-select" data-hdn-filter="priority">
<?php foreach (['all'=>'All priorities','high'=>'High','normal'=>'Review context','low'=>'Lower'] as $value=>$label): ?><option value="<?= $value ?>" <?= $chosen['priority']===$value ? 'selected' : '' ?>><?= $label ?></option><?php endforeach; ?>
</select></label>
<label class="form-label">Characteristic<select class="form-select" data-hdn-filter="feature">
<option value="all">All characteristics</option>
<?php foreach ($analysis['filter_features'] ?? [] as $value=>$label): ?><option value="<?= $escape($value) ?>" <?= $chosen['feature']===$value ? 'selected' : '' ?>><?= $escape($label) ?></option><?php endforeach; ?>
</select></label>
<label class="form-label">Review state<select class="form-select" data-hdn-filter="review">
<?php foreach (['visible'=>'Visible (exclude ignored)','all'=>'All, including ignored','open'=>'Not reviewed','reviewed'=>'Reviewed','ignored'=>'Ignored'] as $value=>$label): ?><option value="<?= $value ?>" <?= $chosen['review']===$value ? 'selected' : '' ?>><?= $label ?></option><?php endforeach; ?>
</select></label>
<label class="form-label">Path contains<input class="form-control" type="search" maxlength="2048" data-hdn-filter="query" value="<?= $escape($chosen['query']) ?>"></label>
<label class="form-label">Minimum hits<?= ($analysis['inventory_kind'] ?? '') === 'php_files' ? ' per exact path' : '' ?><input class="form-control" type="number" min="0" step="1" data-hdn-filter="min_hits" value="<?= $escape($chosen['min_hits']) ?>"></label>
<?php if (($analysis['inventory_kind'] ?? '') === 'php_files'): ?><label class="form-label">Minimum domains<input class="form-control" type="number" min="0" step="1" data-hdn-filter="min_domains" value="<?= $escape($chosen['min_domains']) ?>"></label><?php endif; ?>
</div>
<?php if (empty($analysis['inventory_kind'])): ?><label><input type="checkbox" data-hdn-filter="group_rejected" <?= $chosen['group_rejected'] ? 'checked' : '' ?>> Group already rejected secret-file probes by domain</label><?php endif; ?>
<button type="button" class="button button-secondary" data-hdn-apply-filters>Apply filters</button>
<button type="button" class="button button-secondary" data-hdn-reset-filters>Reset filters</button>
<p class="u-mt10">Matching groups/findings: <?= $escape($analysis['findings_total']) ?> / <?= $escape($analysis['review_total'] ?? $analysis['findings_total']) ?>.
Ignored domain/path entries: <?= $escape($analysis['ignored_contributions'] ?? 0) ?>. Choose “Ignored” or “All” to restore them. Download CSV uses these filters across all pages.</p>
<p>Priority helps choose what to inspect. It never changes protection or proves that a request is malicious.</p>
<p data-hdn-review-note-status role="status"></p>
</div>
