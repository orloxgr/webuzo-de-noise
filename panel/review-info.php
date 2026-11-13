<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }
$reviewInfo = $reviewRow['review_info'] ?? $reviewRow['php_info'] ?? [];
?>
<?php if (!empty($reviewInfo['priority_label'])): ?><strong class="hdn-review-priority" data-hdn-priority="<?= $escape($reviewInfo['priority'] ?? 'normal') ?>"><?= $escape($reviewInfo['priority_label']) ?></strong><?php endif; ?>
<?php if (!empty($reviewInfo['tags'])): ?><p class="hdn-review-tags"><?php foreach ($reviewInfo['tags'] as $tag): ?><span><?= $escape($analysis['filter_features'][$tag] ?? ucwords(str_replace('_',' ',$tag))) ?></span> <?php endforeach; ?></p><?php endif; ?>
<p><?= $escape($reviewInfo['reason'] ?? '') ?></p>
<?php if (!empty($reviewRow['evidence_scope'])): ?><small><?= $escape($reviewRow['evidence_scope']) ?></small><?php endif; ?>
