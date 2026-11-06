<?php
$pageInfo = $listState['pagination'] ?? ['page' => 1, 'pages' => 1, 'total' => 0, 'view' => 'active'];
$historyView = $pageInfo['view'] === 'history';
$listUrl = static function (array $changes) use ($listing, $listTab, $escape): string {
    return '?' . $escape(http_build_query(array_merge($listing, ['act' => 'webuzo-de-noise', 'tab' => $listTab], $changes)));
};
?>
<nav class="hdn-ban-pager u-mb20" aria-label="<?= $escape($listTab) ?> pages">
    <a class="button button-secondary" title="Show live bans and pending changes, 50 records per page." href="<?= $listUrl([$listPrefix . '_view' => 'active', $listPrefix . '_page' => 1]) ?>" <?= !$historyView ? 'aria-current="page"' : '' ?>>Active bans</a>
    <a class="button button-secondary" title="Show completed bans retained in De-Noise history." href="<?= $listUrl([$listPrefix . '_view' => 'history', $listPrefix . '_page' => 1]) ?>" <?= $historyView ? 'aria-current="page"' : '' ?>>History</a>
    <span>Page <?= $escape($pageInfo['page']) ?> / <?= $escape($pageInfo['pages']) ?> · <?= $escape($pageInfo['total']) ?> records</span>
    <?php if ($pageInfo['page'] > 1): ?><a class="button button-secondary" title="Load the previous 50 records." href="<?= $listUrl([$listPrefix . '_view' => $pageInfo['view'], $listPrefix . '_page' => $pageInfo['page'] - 1]) ?>">Previous</a><?php endif; ?>
    <?php if ($pageInfo['page'] < $pageInfo['pages']): ?><a class="button button-secondary" title="Load the next 50 records." href="<?= $listUrl([$listPrefix . '_view' => $pageInfo['view'], $listPrefix . '_page' => $pageInfo['page'] + 1]) ?>">Next</a><?php endif; ?>
</nav>
<?php if ($historyView && empty($read_only)): ?>
<form method="post" class="u-mb20"><?php $fields('history_clear'); ?>
    <input type="hidden" name="history_scope" value="<?= $listPrefix === 'bans' ? 'global' : 'domain' ?>">
    <button class="button button-secondary" type="submit" title="Clear completed history in your current account scope. Live bans, strike counters and Fail2ban history are kept.">Empty history</button>
</form>
<?php endif; ?>
