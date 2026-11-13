<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }
?>
<h2 class="u-mb20">Activity</h2>
<p class="u-mb10">Review matched requests from all available retained logs. A review runs only when requested; opening this panel does not rescan logs.</p>
<form method="post" id="hdn-activity-scan" data-hdn-context="<?= $escape(($actor ?? $headerOwner) . ":" . ($isAdmin ? "all" : $headerOwner)) ?>">
<?php $fields('activity_start'); ?>
<label class="form-label">Site
<select class="form-select" name="activity_domain" title="Filter both the summary and every page of the saved report. This does not rescan logs or change protection rules.">
<option value="all">All sites</option>
<?php $activityDomains = array_unique(array_column($data['sites'] ?? [], 'domain')); sort($activityDomains); foreach ($activityDomains as $domain): ?>
<option value="<?= $escape($domain) ?>"><?= $escape($domain) ?></option>
<?php endforeach; ?>
</select></label>
<label class="form-label">Time window (minutes)
<input class="form-control" type="number" name="analysis_minutes" value="15" min="1" required title="Read every retained activity record within this time window in the background. Results remain limited to domains you may view."></label>
<button type="submit" class="button button-secondary" title="Start a complete read-only activity review. Existing jobs can be resumed and results are paginated without truncation.">Refresh activity</button>
<button type="button" id="hdn-activity-cancel" class="button button-secondary" hidden title="Stop only this review; protection rules and bans are unchanged.">Cancel review</button>
<p id="hdn-activity-progress" class="u-mt10" role="status"></p>
</form>
<?php require $install . '/panel/activity-output.php'; ?>
