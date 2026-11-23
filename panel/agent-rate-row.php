<?php if (!defined('SOFTACULOUS')) { http_response_code(403); exit; } ?>
<?php $base = 'agent_individual[' . $field . '][' . $rowIndex . ']'; ?>
<tr data-hdn-agent-rate-row>
<td><input form="hdn-settings" type="checkbox" name="<?= $escape($base) ?>[enabled]" <?= !empty($rule['enabled']) ? 'checked' : '' ?> aria-label="Enable individual rule" title="Enable this individual budget. Disabling it falls back to a matching group limit, then a blocklist."></td>
<td><input form="hdn-settings" class="form-control" name="<?= $escape($base) ?>[agent]" value="<?= $escape($rule['agent'] ?? '') ?>" aria-label="Bot or literal User-Agent substring" placeholder="Bot / literal User-Agent substring" required spellcheck="false"></td>
<td><input form="hdn-settings" class="form-control" type="number" min="1" step="1" name="<?= $escape($base) ?>[rate]" value="<?= $escape($rule['rate'] ?? '') ?>" aria-label="Individual requests" title="Positive average request rate across all server websites and IPs. Required when enabled."></td>
<td><select form="hdn-settings" class="form-select" name="<?= $escape($base) ?>[unit]" aria-label="Individual rate unit"><option value="m" <?= ($rule['unit'] ?? 'm') === 'm' ? 'selected' : '' ?>>minute</option><option value="s" <?= ($rule['unit'] ?? '') === 's' ? 'selected' : '' ?>>second</option></select></td>
<td><input form="hdn-settings" class="form-control" type="number" min="0" step="1" name="<?= $escape($base) ?>[burst]" value="<?= $escape($rule['burst'] ?? 0) ?>" aria-label="Individual burst" required title="Extra requests allowed in a short burst without queuing. Zero allows no extra burst."></td>
<td><button type="button" class="button button-secondary" data-hdn-agent-remove title="Remove this individual rule from the editor. On Save &amp; Apply, matching group limits or blocklists can apply again.">Remove</button></td>
</tr>
