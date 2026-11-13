<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }

$pageInfo = $listState['pagination'] ?? ['page' => 1, 'pages' => 1, 'total' => 0, 'view' => 'active'];
$historyView = $pageInfo['view'] === 'history';
$listUrl = static function (array $changes) use ($listing, $listTab, $escape): string {
    return '?' . $escape(http_build_query(array_merge($listing, ['act' => 'webuzo-de-noise', 'tab' => $listTab], $changes)));
};
?>
<nav class="hdn-ban-pager u-mb20" aria-label="<?= $escape($listTab) ?> pages">
    <a class="button button-secondary" title="Show live bans and pending changes, Read current bans and pending changes." data-hdn-remote-page href="<?= $listUrl([$listPrefix . '_view' => 'active', $listPrefix . '_page' => 1]) ?>" <?= !$historyView ? 'aria-current="page"' : '' ?>>Active bans</a>
    <a class="button button-secondary" title="Show completed bans retained in De-Noise history." data-hdn-remote-page href="<?= $listUrl([$listPrefix . '_view' => 'history', $listPrefix . '_page' => 1]) ?>" <?= $historyView ? 'aria-current="page"' : '' ?>>History</a>
    <span>Page <?= $escape($pageInfo['page']) ?> / <?= $escape($pageInfo['pages']) ?> · <?= $escape($pageInfo['total']) ?> records</span>
    <?php if ($pageInfo['page'] > 1): ?><a class="button button-secondary" title="Load the previous result page." data-hdn-remote-page href="<?= $listUrl([$listPrefix . '_view' => $pageInfo['view'], $listPrefix . '_page' => $pageInfo['page'] - 1]) ?>">Previous</a><?php endif; ?>
    <?php if ($pageInfo['page'] < $pageInfo['pages']): ?><a class="button button-secondary" title="Load the next result page." data-hdn-remote-page href="<?= $listUrl([$listPrefix . '_view' => $pageInfo['view'], $listPrefix . '_page' => $pageInfo['page'] + 1]) ?>">Next</a><?php endif; ?>
<label>Show per page <select class="form-select" data-hdn-remote-size="bans"><?php foreach ([20,50,100,500,'all'] as $size): ?><option value="<?= $size ?>" <?= ($pageInfo['per_page'] ?? 50) === $size ? 'selected' : '' ?>><?= $size === 'all' ? 'All' : $size ?></option><?php endforeach; ?></select></label>
<a class="button button-secondary" href="<?= $listUrl(['download_list'=>'bans', 'bans_view'=>$pageInfo['view']]) ?>">Download CSV</a>
</nav>
<?php if ($historyView && empty($read_only)): ?>
<form method="post" class="u-mb20"><?php $fields('history_clear'); ?>
    <input type="hidden" name="history_scope" value="<?= $listPrefix === 'bans' ? 'global' : 'domain' ?>">
    <button class="button button-secondary" type="submit" title="Clear completed history in your current account scope. Live bans, strike counters and Fail2ban history are kept.">Empty history</button>
</form>
<?php endif; ?>
