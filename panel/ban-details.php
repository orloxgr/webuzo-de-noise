<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }
 $banDetails = $row['diagnostics'] ?? null; ?>
<details class="hdn-ban-details u-mt10">
<summary title="Show the requests and policy captured when this ban was triggered.">Why was this IP banned?</summary>
<?php if (!$banDetails): ?>
<p>No request details were saved for this older ban.</p>
<?php else: ?>
<p class="u-mt10"><strong><?= $escape($banDetails['count']) ?> matches</strong>;
threshold <?= $escape($banDetails['maxretry']) ?> in <?= $escape($banDetails['findtime']) ?> seconds.
Duration at trigger: <?= empty($banDetails['duration_days']) ? 'permanent' : $escape($banDetails['duration_days']) . ' days' ?>.</p>
<?php if (isset($banDetails['min_distinct_paths'])): ?><p>Minimum different paths: <?= $escape($banDetails['min_distinct_paths']) ?>. Missing static assets: <?= !empty($banDetails['exclude_static']) ? 'excluded' : 'counted' ?>.</p><?php endif; ?>
<p>Last <?= count($banDetails['samples']) ?> matching requests (UTC):</p>
<ul>
<?php foreach ($banDetails['samples'] as $sample): ?>
<li><time><?= $escape(gmdate('Y-m-d H:i:s', (int)$sample['at'])) ?></time>
<?= $escape($sample['domain']) ?> · <?= $escape($sample['method']) ?>
<code><?= $escape($sample['path'] ?: 'Path unavailable in this older log record') ?></code></li>
<?php endforeach; ?>
</ul>
<?php endif; ?>
</details>
<?php unset($banDetails, $sample); ?>
