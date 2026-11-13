<?php if (!defined('SOFTACULOUS')) { http_response_code(403); exit; } ?>
<tr data-hdn-inventory-row>
<td><input type="checkbox" data-hdn-inventory-value="<?= $escape($pathRow['candidate'] ?? '') ?>" <?= empty($pathRow['candidate']) ? 'disabled' : '' ?> aria-label="Select <?= $escape($pathRow['value']) ?>"></td>
<td><code><?= $escape($pathRow['value']) ?></code></td><td><?php $reviewRow = $pathRow; require __DIR__ . '/review-info.php'; ?></td><td><?= $escape($pathRow['count']) ?></td>
<td><?php foreach ($pathRow['domains'] as $source): ?><div><?= $escape($source['domain']) ?> · <?= $escape($source['count']) ?></div><?php endforeach; ?></td>
<td><input type="hidden" data-hdn-inventory-field value="bans-missing_files-list">Selected PHP files
<?php if (empty($pathRow['candidate'])): ?><small><?= $escape($pathRow['php_info']['append_reason'] ?? 'This exact path is not accepted by the file-rule validator.') ?></small><?php endif; ?><?php require __DIR__ . '/review-note-controls.php'; ?></td>
</tr>
