<?php
define('SOFTACULOUS', true);
// argv[2] is catalog metadata exported from the actual Python module in the lab.
$install = $argv[1];
$data = ['presets' => json_decode(file_get_contents($argv[2]), true, 512, JSON_THROW_ON_ERROR)];
$escape = static fn($v) => htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$policy = ['search_agents' => ['My custom agent', 'gOoGlEbOt-ImAgE'], 'search_agents_enabled' => false];
?>
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style><?php readfile($install.'/panel/ui.css'); ?></style></head><body>
<div id="hdn-container" style="padding:16px">
<form id="hdn-settings" method="post"><input type="hidden" name="action" value="save"></form>
<?php require $install.'/panel/agent-lists.php'; ?>
<button form="hdn-settings" type="submit">Save &amp; Apply</button></div>
<?php require $install.'/panel/agent-presets.php'; ?>
<script id="hdn-probe-presets" type="application/json">{}</script>
<script><?php readfile($install.'/panel/settings.js'); ?></script>
</body></html>
