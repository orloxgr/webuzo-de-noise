<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }
 $analysis = $data['analysis'] ?? null; ?>
<div id="hdn-analysis-output">
<?php if (is_array($analysis)): ?>
<div class="u-mt20">
<h3 class="u-mb10">Review results · <?= $escape($analysis['minutes']) ?> minutes</h3>
<p class="u-mb10"><?= !empty($analysis['partial']) ? 'Incomplete coverage; see read errors below.' : 'Available retained logs processed in full.' ?><br>
Records: <?= $escape($analysis['totals']['requests'] ?? 0) ?> · Domains: <?= $escape($analysis['domains']) ?> ·
<?= $escape(round($analysis['bytes_read'] / 1048576, 2)) ?> MiB read · <?= $escape($analysis['elapsed_seconds']) ?> sec.</p>
<p class="u-mb10"><?= $escape($analysis['totals']['unparsed'] ?? 0) ?> malformed lines and <?= $escape($analysis['totals']['incomplete_lines'] ?? 0) ?> incomplete trailing lines skipped.</p>
<?php if (isset($analysis['totals']['image_records_excluded'])): ?><p class="u-mb10">Image requests are excluded from findings, including missing images and icons. <?= $escape($analysis['totals']['image_records_excluded']) ?> image records remain included in the traffic totals. Known secret-file probes are reported separately.</p><?php endif; ?>
<p class="u-mb10">Showing <?= $escape(count($analysis['findings'])) ?> of <?= $escape($analysis['findings_total']) ?> review findings. All findings are available through the report pages. These are diagnostic suggestions, not legitimacy verdicts.</p>
<p class="u-mb10"><?= $escape($analysis['verification']) ?>. Verification uses the address already recorded by the server; proxy address configuration can affect the result.</p>
<p class="u-mb10"><?= $escape($analysis['note']) ?> Layered logs may contain duplicate records. All available numbered rotations, including gzip/bzip2/xz files, are considered for the selected interval. Missing timing/cache fields are not inferred.</p>
<?php if (!empty($analysis['unavailable_domains'])): ?><p class="u-mb10">No recent readable log sample: <?= $escape(implode(', ', $analysis['unavailable_domains'])) ?>.</p><?php endif; ?>
<?php foreach ($analysis['errors'] ?? [] as $row): ?><p class="u-mb10"><?= $escape($row['domain'] . ' · ' . $row['file'] . ': ' . $row['message']) ?></p><?php endforeach; ?>
<?php if (empty($analysis['findings'])): ?><p class="u-mb10">No suggestions met the review thresholds in the selected window. This does not prove safety, absence of traffic or complete coverage.</p><?php endif; ?>
<?php require __DIR__ . '/review-filters.php'; ?>
<?php $reviewPage = $analysis; require __DIR__ . '/review-pagination.php'; ?>
<?php foreach ($analysis['findings'] ?? [] as $finding): ?>
<?php if (!empty($finding['grouped_probes'])) { require __DIR__ . '/rejected-probes.php'; continue; } ?>
<article class="hdn-analysis-finding u-mt20 u-mb20">
<h4 class="u-mb10"><?= $escape(ucfirst($finding['kind']) . ' · ' . $finding['title']) ?></h4>
<p class="u-mb10"><strong><?= $escape($finding['domain']) ?></strong> · <code><?= $escape($finding['path']) ?></code></p>
<?php if ($finding['parameters']): ?><p class="u-mb10">Parameter names: <code><?= $escape(implode(', ', $finding['parameters'])) ?></code></p><?php endif; ?>
<p class="u-mb10">Records: <?= $escape($finding['count']) ?> · peak <?= $escape($finding['peak_per_minute']) ?>/minute ·
distinct clients: <?= $escape($finding['clients']) ?> · parameter combinations: <?= $escape($finding['combinations']) ?><?= !empty($finding['distinct_capped']) ? ' (distinct counts are capped lower bounds)' : '' ?>.</p>
<p class="u-mb10">HTTP: <?= $escape(implode(' · ', array_map(static fn($code, $count) => $code . ': ' . $count, array_keys($finding['statuses']), $finding['statuses']))) ?>.</p>
<p class="u-mb10">Declared agents (not identity proof): <?= $escape(implode(' · ', array_map(static fn($agent, $count) => $agent . ': ' . $count, array_keys($finding['agents']), $finding['agents']))) ?>.</p>
<?php if ($finding['verified_google'] || $finding['unconfirmed_google']): ?><p class="u-mb10"><?php if (!empty($analysis['verified_google_requested'])): ?>Googlebot records: <?= $escape($finding['verified_google']) ?> matched published Google ranges · <?= $escape($finding['unconfirmed_google']) ?> not confirmed. Neither result establishes request legitimacy.<?php else: ?>Googlebot source verification: not requested.<?php endif; ?></p><?php endif; ?>
<p class="u-mb10">Request timing: <?= $finding['mean_request_ms'] === null ? 'not recorded' : $escape($finding['mean_request_ms'] . ' ms mean, ' . $finding['request_time_samples'] . ' recorded samples') ?>.
Upstream timing: <?= $finding['mean_upstream_ms'] === null ? 'not recorded' : $escape($finding['mean_upstream_ms'] . ' ms mean, ' . $finding['upstream_time_samples'] . ' recorded samples') ?>.
Cache: <?= $finding['cache'] ? $escape(implode(' · ', array_map(static fn($key, $count) => $key . ': ' . $count, array_keys($finding['cache']), $finding['cache']))) : 'not recorded' ?>.</p>
<?php $reviewRow = $finding; require __DIR__ . '/review-info.php'; ?>
<?php if (!empty($finding['endpoint_work'])): ?><p><strong>Application work:</strong> <?= $escape(implode(' · ', $finding['endpoint_work'])) ?></p><?php endif; ?>
<p>Methods: <?= $escape(json_encode($finding['methods'] ?? [])) ?><?php if (isset($finding['first'],$finding['last'])): ?> · <?= $escape(gmdate('Y-m-d H:i:s',(int)$finding['first'])) ?> – <?= $escape(gmdate('Y-m-d H:i:s',(int)$finding['last'])) ?> UTC<?php endif; ?></p>
<?php if (!empty($finding['log_sources'])): ?><p>Native access logs: <?= $escape(implode(', ', $finding['log_sources'])) ?></p><?php endif; ?>
<p><?= $escape($finding['advice']) ?></p>
<?php require __DIR__ . '/review-note-controls.php'; ?>
<?php if (!empty($finding['recommendations'])): ?>
<h5 class="u-mt10 u-mb10">Suggested next steps · <?= $escape($finding['domain']) ?></h5>
<ol><?php foreach ($finding['recommendations'] as $step): ?><li class="u-mb10"><strong><?= $escape($step['title']) ?></strong> — <?= $escape($step['detail']) ?></li><?php endforeach; ?></ol>
<?php endif; ?>
<?php if (!empty($finding['filter_candidate'])): $candidate = $finding['filter_candidate']; ?>
<p class="u-mt10 u-mb10"><strong>Filter candidate for review</strong> · No rule has been created.</p>
<p>Domain: <code><?= $escape($candidate['domain']) ?></code><br>
Path: <code><?= $escape($candidate['path']) ?></code><br>
Parameter names: <code><?= $escape(implode(', ', $candidate['parameters'])) ?></code><br>
Observed crawler names: <code><?= $escape($candidate['observed_crawlers'] ? implode(', ', $candidate['observed_crawlers']) : 'None identified') ?></code></p>
<p>Review these fields in Filtered URLs below. Choose the crawler names, action and rate yourself; apply only to this domain. A 404 or IP ban is not suggested by this finding.</p>
<?php endif; ?>
</article>
<?php endforeach; ?>

<h4 class="u-mt20 u-mb10">Read coverage</h4>
<div class="hdn-scoped-table-wrap"><table class="table" data-hdn-list="Log coverage"><thead><tr><th>Domain / native log</th><th>Records in window</th><th>Coverage</th></tr></thead><tbody>
<?php foreach ($analysis['coverage'] ?? [] as $row): ?>
<tr><td><?= $escape($row['domain'] . ' · ' . $row['source'] . '/' . $row['file']) ?></td><td><?= $escape($row['records']) ?></td><td><?= $escape((!empty($row['partial']) ? 'Partial · ' : '') . $row['note']) ?></td></tr>
<?php endforeach; ?></tbody></table></div>
</div>
<?php endif; ?>
</div>
