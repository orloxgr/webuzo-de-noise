<?php if (!defined('SOFTACULOUS') || !isset($data,$escape)) { http_response_code(403); exit; }
$selected404 = $policy['endpoint_404'] ?? ['enabled'=>false,'paths'=>[],'targets'=>[],'duration_seconds'=>86400];
$seconds404=$selected404['duration_seconds'];$unit404='seconds';$duration404=$seconds404;
foreach (['days'=>86400,'hours'=>3600,'minutes'=>60] as $label=>$factor) if ($seconds404%$factor===0) { $unit404=$label;$duration404=intdiv($seconds404,$factor);break; }
?>
<details class="box-collapse hdn-endpoint-section u-mb20" id="hdn-endpoint404-box"><summary class="box-collapse-header">Ban after repeated HTTP 404s for selected paths</summary>
<div class="box-collapse-content">
<p class="u-mt10">Ban after the configured number of actual final 404 responses within the counting window, per IP across the selected paths and domains, in Enforce. Repeated requests to the same path count; the ban covers websites server-wide. Existing files/routes that return 200, redirects or other statuses keep their normal routing. This list does not create a 404 or a 403. Off and Observe do not ban. Maintenance applies the ban after reading the request.</p>
<label class="form-label u-block"><input form="hdn-settings" type="checkbox" name="endpoint404_enabled" <?= $selected404['enabled']?'checked':'' ?>> Enabled</label>
<div class="hdn-wp-grid u-mt10"><label class="form-label">Ban after X attempts
<input form="hdn-settings" class="form-control" type="number" min="1" name="endpoint404_maxretry" value="<?= $escape($selected404['maxretry'] ?? 1) ?>" required title="Count actual 404 responses from the same IP for selected paths. Set 1 to ban after its first matching 404."></label>
<label class="form-label">Counting window (seconds)
<input form="hdn-settings" class="form-control" type="number" min="1" name="endpoint404_findtime" value="<?= $escape($selected404['findtime'] ?? 300) ?>" required></label></div>
<label class="form-label u-block u-mt10">Exact paths — one per line, any extension
<textarea form="hdn-settings" class="form-control" name="endpoint404_paths" id="hdn-endpoint404-paths" rows="8" spellcheck="false" placeholder="/bak.sql.gz&#10;/missing-scan.js&#10;/unwanted-probe.php"><?= $escape(implode("\n",$selected404['paths'])) ?></textarea></label>
<div class="hdn-wp-grid u-mt10"><label class="form-label">Ban duration (0 = permanent)<input form="hdn-settings" class="form-control" type="number" min="0" name="endpoint404_duration" value="<?= $escape($duration404) ?>" required></label>
<label class="form-label">Unit<select form="hdn-settings" class="form-select" name="endpoint404_unit"><?php foreach (['minutes','hours','days','seconds'] as $choice): ?><option value="<?= $choice ?>" <?= $choice===$unit404?'selected':'' ?>><?= ucfirst($choice) ?></option><?php endforeach; ?></select></label></div>
<label class="form-label u-block u-mt10">Domains (empty selection means all web domains)<select form="hdn-settings" class="form-select" name="endpoint404_targets[]" id="hdn-endpoint404-targets" multiple size="4">
<?php $known404=[];foreach ($data['sites']??[] as $site):if (($site['kind']??'web')!=='web') continue;$known404[]=$site['key']; ?><option value="<?= $escape($site['key']) ?>" <?= in_array($site['key'],$selected404['targets'],true)?'selected':'' ?>><?= $escape($site['domain'].' · '.$site['owner']) ?></option><?php endforeach;foreach (array_diff($selected404['targets'],$known404) as $old): ?><option value="<?= $escape($old) ?>" selected><?= $escape($old) ?> (unavailable)</option><?php endforeach; ?>
</select><small class="hdn-select-help">Press CTRL to select/deselect</small></label>
<p>New or re-enabled selections count requests from activation onward. Earlier retained 404s are not retroactively banned. Native exclusions, Never-ban IPs and server-address protection apply. Appending results keeps this switch, attempt threshold, counting window and duration unchanged; review and Save &amp; Apply.</p>
<p id="hdn-endpoint404-message" role="status"></p>
</div></details>
