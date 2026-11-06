<?php
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }

$renderRule = static function (string $module, $index, array $rule) use ($escape, $data): void {
    $name = $module . '[' . $index . ']';
    $field = static fn($key) => $escape($name . '[' . $key . ']');
    $filter = $module === 'filters';
    $targets = $rule['targets'] ?? [];
    ?>
    <div class="hdn-rule u-mb20" data-module="<?= $module ?>">
        <label class="form-label u-block">Name <input form="hdn-settings" class="form-control" name="<?= $field('id') ?>" value="<?= $escape($rule['id']) ?>" pattern="[a-z][a-z0-9_]{0,31}" required></label>
        <label class="form-label u-block u-mt10"><input form="hdn-settings" type="checkbox" name="<?= $field('enabled') ?>" <?= !empty($rule['enabled']) ? 'checked' : '' ?>> Enabled</label>
        <label class="form-label u-block">URL <?= $filter ? 'path prefix' : 'directory' ?>
            <input form="hdn-settings" class="form-control" name="<?= $field('path') ?>" value="<?= $escape($rule['path']) ?>" required></label>
        <?php if ($filter): ?>
        <label class="form-label u-block u-mt10">Query parameter names (one per line)
            <textarea form="hdn-settings" class="form-control" name="<?= $field('parameters') ?>" rows="3" required><?= $escape(implode("\n", $rule['parameters'])) ?></textarea></label>
        <label class="form-label u-block u-mt10">Crawler names (one literal substring per line)
            <textarea form="hdn-settings" class="form-control" name="<?= $field('agents') ?>" rows="4" required><?= $escape(implode("\n", $rule['agents'])) ?></textarea></label>
        <button type="button" class="button button-secondary u-mt10" data-hdn-filter-agents title="Append the optional search crawler names to this rule only. Keep its current action, rate, domains and other crawler names. Does not add a global User-Agent block.">Add optional search crawlers to this rule</button>
        <label class="form-label u-block u-mt10">Action <select form="hdn-settings" class="form-select" name="<?= $field('rule_action') ?>">
            <option value="limit" <?= $rule['action'] === 'limit' ? 'selected' : '' ?>>Rate limit</option>
            <option value="block" <?= $rule['action'] === 'block' ? 'selected' : '' ?>>Block matching crawlers on these URLs</option>
        </select></label>
        <label class="form-label u-block u-mt10">Requests per minute, per crawler and domain, across all client IPs
            <input form="hdn-settings" class="form-control" name="<?= $field('rate') ?>" type="number" min="1" value="<?= $escape($rule['rate']) ?>" required></label>
        <label class="form-label u-block u-mt10">Burst allowance
            <input form="hdn-settings" class="form-control" name="<?= $field('burst') ?>" type="number" min="0" value="<?= $escape($rule['burst']) ?>" required></label>
        <?php else: ?>
        <label class="form-label u-block u-mt10">File extensions (without dots)
            <input form="hdn-settings" class="form-control" name="<?= $field('extensions') ?>" value="<?= $escape(implode(' ', $rule['extensions'])) ?>" required></label>
        <?php endif; ?>
        <label class="form-label u-block u-mt10">Domains (empty selection means all domains)
        <select form="hdn-settings" class="form-select" name="<?= $field('targets') ?>[]" multiple size="4">
            <?php $known = []; foreach ($data['sites'] ?? [] as $site): if (($site['kind'] ?? 'web') === 'mail') continue; $known[] = $site['key']; ?>
            <option value="<?= $escape($site['key']) ?>" <?= in_array($site['key'], $targets, true) ? 'selected' : '' ?>><?= $escape($site['domain'] . ' · ' . $site['owner']) ?></option>
            <?php endforeach; foreach (array_diff($targets, $known) as $old): ?>
            <option value="<?= $escape($old) ?>" selected><?= $escape($old) ?> (unavailable)</option>
            <?php endforeach; ?>
        </select></label>
        <?php if ($filter): ?>
        <button type="button" class="button button-secondary u-mt10" data-hdn-robots title="Preview robots.txt directives for this rule's path and parameter names. This only prepares text for review; it does not write a website file or save this rule. Use only when these filtered URLs should stay out of search.">Preview robots.txt suggestions</button>
        <?php endif; ?>
        <button type="button" class="button button-secondary u-mt10" data-hdn-remove>Remove rule</button>
    </div>
    <?php
};
foreach (isset($ruleModule) ? [$ruleModule => $ruleModule === 'filters' ? 'Filtered URL crawling' : 'Missing static files'] : ['filters' => 'Filtered URL crawling', 'static' => 'Missing static files'] as $module => $title): ?>
<section class="u-mb20">
    <h2 class="u-mb20"><?= $escape($title) ?></h2>
        <?php if ($module === 'filters') require $install . '/panel/log-analysis.php'; ?>
        <p class="u-mb10"><?= $module === 'filters'
            ? 'Match selected crawler names, a URL path and query parameter names. Ordinary visitors and unmatched URLs keep their current routing.'
            : 'Return 404 for missing files in selected directories. Existing files keep their current routing.' ?></p>
        <?php foreach ($data['presets']['rules'][$module] ?? [] as $preset): ?>
        <div class="u-mb10">
            <button type="button" class="button button-secondary" data-hdn-add="<?= $module ?>" data-hdn-rule-preset="<?= $escape($preset['key']) ?>" title="<?= $escape($preset['description']) ?>"><?= $escape($preset['title']) ?></button>
            <p class="u-mt10"><?= $escape($preset['description']) ?></p>
        </div>
        <?php endforeach; ?>
        <p class="u-mb10" role="status" id="hdn-<?= $module ?>-message"></p>
        <div id="hdn-<?= $module ?>-rows">
        <?php foreach (is_array($policy[$module] ?? null) ? $policy[$module] : [] as $index => $rule) { $renderRule($module, $index, $rule); } ?>
        </div>
        <button type="button" class="button button-secondary" data-hdn-add="<?= $module ?>">Add rule</button>
        <?php if ($module === 'filters'): ?>
        <div id="hdn-robots-preview" class="u-mt20" hidden>
            <h3 class="u-mb10">Robots.txt suggestions</h3>
            <p id="hdn-robots-scope" class="u-mb10"></p>
            <p class="u-mb10">Use only for filtered URLs that should not appear in search. Merge these directives into the appropriate existing User-agent groups in each selected site's robots.txt, including any specific crawler groups. Review existing rules first. No website files are changed here.</p>
            <label class="form-label" for="hdn-robots-text">Suggested directives</label>
            <textarea id="hdn-robots-text" class="form-control" rows="8" readonly spellcheck="false" title="Preview only. These lines are not submitted by Save & Apply and do not change robots.txt."></textarea>
            <button type="button" class="button button-secondary u-mt10" id="hdn-robots-copy" title="Copy the reviewed directives to the clipboard. Nothing is installed or written to any domain.">Copy suggestions</button>
            <p id="hdn-robots-message" class="u-mt10" role="status"></p>
        </div>
        <?php endif; ?>
        <?php $webSites = array_values(array_filter($data['sites'] ?? [], static fn($site) => ($site['kind'] ?? 'web') === 'web'));
        if ($module === 'static' && !empty($webSites)): ?>
        <h3 class="u-mt20 u-mb10">File exceptions by domain</h3>
        <label class="form-label" for="hdn-exception-domain">Domain</label>
        <select form="hdn-settings" class="form-select u-mb10" id="hdn-exception-domain">
            <?php foreach ($webSites as $site): ?>
            <option value="<?= $escape($site['key']) ?>"><?= $escape($site['domain'] . ' · ' . $site['owner']) ?></option>
            <?php endforeach; ?>
        </select>
        <?php foreach ($webSites as $index => $site):
            $exceptions = $policy['static_exceptions'][$site['key']] ?? []; ?>
        <div data-hdn-exception-domain="<?= $escape($site['key']) ?>" <?= $index !== 0 ? 'hidden' : '' ?>>
            <label class="form-label u-block" for="hdn-exceptions-<?= $index ?>">Allowed file paths — one per line</label>
            <textarea form="hdn-settings" class="form-control" rows="4" spellcheck="false" id="hdn-exceptions-<?= $index ?>" name="static_exceptions[<?= $escape($site['key']) ?>]" placeholder="/wp-content/plugins/example/assets/app.js.map"><?= $escape(implode("\n", is_array($exceptions) ? $exceptions : [])) ?></textarea>
        </div>
        <?php endforeach; ?>
        <p class="u-mt10">Exact URL paths, starting with /. Exceptions use the domain's normal routing for every query string and apply to its aliases too. Save &amp; Apply to save all domains.</p>
        <?php endif; ?>
</section>
<template id="hdn-<?= $module ?>-template">
<?php $renderRule($module, '__INDEX__', $module === 'filters'
    ? ['id' => '__ID__', 'enabled' => false, 'path' => '/', 'parameters' => [], 'agents' => [], 'action' => 'limit', 'rate' => '', 'burst' => 0, 'targets' => []]
    : ['id' => '__ID__', 'enabled' => true, 'path' => '/wp-content/', 'extensions' => ['map'], 'targets' => []]); ?>
</template>
<?php endforeach; ?>
<?php if (!isset($ruleModule) || $ruleModule === 'static'): ?>
<script type="application/json" id="hdn-rule-presets"><?= json_encode($data['presets']['rules'] ?? [], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
<?php endif; ?>
