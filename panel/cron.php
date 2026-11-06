<h2 class="u-mb20">Spread WordPress cron jobs</h2>
<p class="u-mb20">Spread existing WordPress jobs across the hour. The interval columns show how often each job runs; exact clock minutes are under Schedule details. Selected jobs remain editable in Webuzo CRON. No schedule changes until you apply it.</p>
<form method="post" class="u-mb20"><?php $fields('cron_preview'); ?>
<label class="form-label u-block u-mb10">Minimum interval (minutes)<input class="form-control" type="number" name="cron_min" min="1" value="<?= $escape($data['cron']['minimum'] ?? 5) ?>" required></label>
<label class="form-label u-block u-mb10">Maximum interval (minutes)<input class="form-control" type="number" name="cron_max" min="1" value="<?= $escape($data['cron']['maximum'] ?? 15) ?>" required></label>
<button class="button button-secondary" type="submit">Generate preview</button></form>
<?php if (!empty($data['cron']['error'])): ?><div class="alert alert-danger" role="alert"><?= $escape($data['cron']['error']) ?></div>
<?php elseif (!empty($data['cron']['id'])): ?>
<form method="post"><?php $fields('cron_apply'); ?>
<input type="hidden" name="plan_id" value="<?= $escape($data['cron']['id']) ?>">
<div class="hdn-cron-table-wrap"><table class="table hdn-cron-table"><thead><tr><th>Select</th><th>Account / job</th><th>Website</th><th>Previous interval</th><th>New interval</th><th>Status</th></tr></thead><tbody>
<?php foreach ($data['cron']['rows'] as $row): ?><tr>
<td><input type="checkbox" name="cron_jobs[]" value="<?= $escape($row['key']) ?>" checked></td>
<td><?= $escape($row['key']) ?></td><td><?= $escape($row['site'] ?? $row['label']) ?>
<details class="u-mt10"><summary>Schedule details</summary>
<div class="u-mt10"><strong>Previous clock minutes:</strong> <code><?= $escape($row['before']) ?></code></div>
<div class="u-mt10"><strong>New clock minutes:</strong> <code><?= $escape($row['after']) ?></code></div>
<div class="u-mt10"><strong>Path:</strong> <code><?= $escape($row['label']) ?></code></div></details></td>
<td><?= $escape($row['before_label'] ?? $row['before']) ?></td><td><?= $escape($row['after_label'] ?? $row['after']) ?></td><td><?= $escape($row['state']) ?></td>
</tr><?php endforeach; ?></tbody></table></div>
<button class="button u-mt20" type="submit">Apply selected schedules</button>
<button class="button button-secondary u-mt20" type="submit" name="restore_cron" value="1">Restore selected original schedules</button>
</form>
<?php if (empty($data['cron']['rows'])): ?><p>No eligible active WordPress cron jobs were found.</p><?php endif; ?>
<?php endif; ?>
