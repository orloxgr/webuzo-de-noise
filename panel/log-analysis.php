<?php $analysis = $data['analysis'] ?? null; ?>
<section class="hdn-analysis u-mb20" aria-label="Log analysis">
<h3 class="u-mb10">Analyze logs for suggestions</h3>
<p class="u-mb10">Review actual URL patterns before choosing a rule. High traffic, a crawler name or repeated 404s do not establish abuse. This review never applies rules, returns new 404s or bans visitors.</p>
<form method="post" id="hdn-log-scan" data-hdn-context="<?= $escape(($actor ?? $headerOwner) . ":" . ($isAdmin ? "all" : $headerOwner)) ?>">
<?php $fields('log_scan_start'); ?>
<div class="hdn-wp-grid">
<label class="form-label">Domain
<select class="form-select" name="analysis_target" title="Analyze one existing web domain, or all web domains separately. Findings remain scoped to their original domain; no rule is created.">
<option value="all" <?= ($_POST['analysis_target'] ?? 'all') === 'all' ? 'selected' : '' ?>>All web domains</option>
<?php foreach ($data['sites'] ?? [] as $site): if (($site['kind'] ?? 'web') !== 'web') continue; ?>
<option value="<?= $escape($site['key']) ?>" <?= ($_POST['analysis_target'] ?? '') === $site['key'] ? 'selected' : '' ?>><?= $escape($site['domain'] . ' · ' . $site['owner']) ?></option>
<?php endforeach; ?>
</select></label>
<label class="form-label">Time window
<input class="form-control" type="number" name="analysis_minutes" min="1" value="<?= $escape($_POST['analysis_minutes'] ?? 30) ?>" list="hdn-analysis-windows" required title="Review all retained log records in this many minutes. Runs in the background until completion or cancellation.">
<datalist id="hdn-analysis-windows"><option value="30">30 minutes</option><option value="360">6 hours</option><option value="1440">24 hours</option></datalist></label>
</div>
<label class="form-label u-block u-mt10 u-mb10"><input type="checkbox" name="analysis_verify_google" <?= isset($_POST['analysis_verify_google']) ? 'checked' : '' ?> title="Check logged Googlebot addresses against Google's published common-crawler ranges. Downloads the public range list only when requested, with a private 24-hour cache. No visitor IPs or log contents are sent. This verifies a source range, not whether its requests are useful or harmless."> Verify declared Googlebot against published Google ranges</label>
<button type="submit" class="button button-secondary" title="Run a complete low-priority review in the background. The worker stops when finished or cancelled; no periodic collector or automatic rule application is added.">Analyze logs</button>
<button type="button" id="hdn-analysis-cancel" title="Stop only this review; protection rules and unsaved edits stay unchanged." class="button button-secondary" hidden>Cancel review</button>
<p id="hdn-analysis-progress" class="u-mt10" role="status"></p>
</form>
<?php require $install . '/panel/analysis-output.php'; ?>
</section>
