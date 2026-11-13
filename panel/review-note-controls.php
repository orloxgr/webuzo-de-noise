<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }
if (empty($reviewRow['review_marks'])) return;
$reviewValue = $reviewRow['value'] ?? $reviewRow['path'];
?>
<div class="hdn-review-note u-mt10" data-hdn-review-item="<?= $escape($reviewValue) ?>">
<label>Domain / review state<select class="form-select" data-hdn-note-domain>
<?php if (count($reviewRow['review_marks']) > 1): ?><option value="">Choose domain</option><?php endif; ?>
<?php foreach ($reviewRow['review_marks'] as $mark): ?><option value="<?= $escape($mark['domain']) ?>"><?= $escape($mark['domain'] . ' · ' . $mark['state']) ?></option><?php endforeach; ?>
</select></label>
<button type="button" class="button button-secondary" data-hdn-review-mark="reviewed">Mark reviewed</button>
<button type="button" class="button button-secondary" data-hdn-review-mark="ignored">Ignore in findings</button>
<button type="button" class="button button-secondary" data-hdn-review-mark="open">Reopen</button>
<small>Applies to this exact path on the selected domain, including future reviews. Protection rules stay unchanged.</small>
</div>
