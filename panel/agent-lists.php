<?php
if (!defined('SOFTACULOUS') || !isset($data, $escape)) { http_response_code(403); exit; }
?>
    <h2 class="u-mb20">User-Agent lists</h2>
    <p class="u-mb20">One literal substring per line. Case-insensitive. Each list has its own switch.</p>
    <div class="hdn-agent-grid">
    <?php foreach ($data['presets']['agent_categories'] ?? [] as $field => $category): $isOther = $field === 'agents'; ?>
    <<?= $isOther ? 'details' : 'section' ?> class="box-collapse hdn-agent-card<?= $isOther ? ' hdn-agent-other' : '' ?>">
    <?php if ($isOther): ?><summary class="box-collapse-header"><?= $escape($category['title']) ?></summary><?php endif; ?>
    <div class="box-collapse-content">
    <?php if (!$isOther): ?><h3 class="u-mb10"><?= $escape($category['title']) ?></h3><?php endif; ?>
    <p class="u-mb10"><?= $escape($category['description']) ?></p>
    <label class="form-label u-block u-mb10"><input form="hdn-settings" type="checkbox" name="<?= $field ?>_enabled" <?= !array_key_exists($field . '_enabled', $policy) || $policy[$field . '_enabled'] ? 'checked' : '' ?>> Enable this list</label>
    <label class="form-label" for="<?= $field ?>"><?= $escape($category['title']) ?> blocklist</label>
    <textarea form="hdn-settings" class="form-control u-mb10" rows="6" id="<?= $field ?>" name="<?= $field ?>" spellcheck="false"><?= $escape(implode("\n", $policy[$field] ?? [])) ?></textarea>
    <div class="hdn-inventory-actions">
    <?php if ($field === 'search_agents'): ?>
    <button type="button" class="button button-secondary" data-hdn-preset="search_additional" data-hdn-agent-field="search_agents" title="Append alternative, regional and specialized search crawlers to this blocklist. They may still bring useful traffic, depending on your audience. Review before Save &amp; Apply. No settings are saved or enabled by this button.">Add additional search bots</button>
    <button type="button" class="button button-secondary" data-hdn-preset="search_major" data-hdn-agent-field="search_agents" title="Append Google, Bing, Apple, Meta and AI search crawlers to this blocklist. Blocking them can reduce search visibility and AI citations. Review before Save &amp; Apply. No settings are saved or enabled by this button.">Add major search &amp; AI bots</button>
    <?php else: ?>
    <button type="button" class="button button-secondary" data-hdn-preset="<?= $field ?>" data-hdn-agent-field="<?= $field ?>" title="Append this category's suggested names to its blocklist. Review the names before Save &amp; Apply. No settings are saved or enabled by this button.">Add suggested agents</button>
    <?php endif; ?>
    <button type="button" class="button button-secondary" data-hdn-append-analyzed="<?= $field ?>" aria-describedby="hdn-analyzed-<?= $field ?>" title="Append recognized names from the latest completed analysis to this blocklist, across all result pages. Review before saving; a request alone does not make a bot malicious." disabled>Append analyzed agents</button>
    </div>
    <?php if ($field === 'search_agents'): ?><p class="u-mt10">Both buttons add names to this blocklist. Additional covers alternative, regional and specialized search engines. Major search &amp; AI includes Google, Bing, Meta, ChatGPT, Claude and Perplexity; blocking these can reduce visibility. Neither button saves settings.</p><?php endif; ?>
    <p class="u-mt10" id="hdn-analyzed-<?= $field ?>" role="status">Uses the latest completed agent analysis, across all result pages.</p>
    <?php if ($isOther): ?><p>Append analyzed agents includes recognized crawlers and fetch clients, including generic clients and names with an unconfirmed purpose. Generic clients such as Go-http-client and quic-go are not bulk suggestions: legitimate integrations also use them. Review individual names before blocking. Unknown agents and browser strings remain individually selectable in the results.</p><?php endif; ?>
    </div></<?= $isOther ? 'details' : 'section' ?>>
    <?php endforeach; ?>
    </div>
    <p class="u-mt10">Lists describe crawler purposes, not whether requests are malicious. Suggested entries are optional. To limit crawlers only on particular URLs, use Filtered URLs.</p>
