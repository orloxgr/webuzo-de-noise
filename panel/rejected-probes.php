<?php if (!defined('SOFTACULOUS')) { http_response_code(403); exit; } ?>
<article class="hdn-analysis-finding u-mt20 u-mb20">
<h4><?= $escape($finding['domain']) ?> · Rejected secret-file probes</h4>
<p><?= $escape($finding['count']) ?> rejected requests · <?= count($finding['grouped_probes']) ?> exact paths. No successful response was recorded in these findings. The status does not identify which protection rejected them.</p>
<details><summary>View exact paths and evidence</summary>
<table class="table" data-hdn-list="Rejected probe paths"><thead><tr><th>Path</th><th>Hits</th><th>HTTP / declared agents</th><th>Review</th></tr></thead><tbody>
<?php foreach ($finding['grouped_probes'] as $probe): ?>
<tr><td><code><?= $escape($probe['path']) ?></code></td><td><?= $escape($probe['count']) ?></td>
<td><?= $escape(json_encode($probe['statuses'])) ?><br><?= $escape(json_encode($probe['agents'] ?? [])) ?></td>
<td><?php $reviewRow = $probe; require __DIR__ . '/review-note-controls.php'; ?></td></tr>
<?php endforeach; ?>
</tbody></table>
</details>
</article>
