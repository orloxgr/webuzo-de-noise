<?php if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }
$pageInfo = $reviewPage;
?>
<nav class="hdn-list-controls u-mt10 u-mb20" aria-label="Review results">
<label>Show per page <select data-hdn-review-size class="form-select">
<?php foreach ([20,50,100,500,'all'] as $size): ?><option value="<?= $size ?>" <?= ($pageInfo['per_page'] ?? 20) === $size ? 'selected' : '' ?>><?= $size === 'all' ? 'All' : $size ?></option><?php endforeach; ?>
</select></label>
<span>Page <?= $escape($pageInfo['page'] ?? 1) ?> / <?= $escape($pageInfo['pages'] ?? 1) ?> · <?= $escape($pageInfo['findings_total'] ?? 0) ?> records</span>
<?php if (($pageInfo['page'] ?? 1) > 1): ?><button type="button" class="button button-secondary" data-hdn-analysis-page="<?= $pageInfo['page']-1 ?>">Previous</button><?php endif; ?>
<?php if (($pageInfo['page'] ?? 1) < ($pageInfo['pages'] ?? 1)): ?><button type="button" class="button button-secondary" data-hdn-analysis-page="<?= $pageInfo['page']+1 ?>">Next</button><?php endif; ?>
<button type="button" class="button button-secondary" <?= ($pageInfo['inventory_kind'] ?? '') === 'agents' ? 'data-hdn-export-agents' : 'data-hdn-export-review' ?> title="Download every result in this saved list and its current site filter, across all pages.">Download CSV</button>
<span data-hdn-export-status role="status"></span>
</nav>
