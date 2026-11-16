<?php
if (!defined('SOFTACULOUS') || !isset($data, $escape)) { http_response_code(403); exit; }
?>
<script type="application/json" id="hdn-agent-presets"><?= json_encode(array_merge(array_map(static fn($category) => $category['entries'], $data['presets']['agent_categories'] ?? []), array_intersect_key($data['presets'] ?? [], array_flip(['search_additional', 'search_major']))), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
