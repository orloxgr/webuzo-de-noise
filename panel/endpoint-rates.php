<?php if (!defined('SOFTACULOUS') || !isset($data,$escape)) { http_response_code(403); exit; } ?>
    <?php foreach (['login' => 'WordPress login — POST /wp-login.php', 'xmlrpc' => 'WordPress XML-RPC — POST /xmlrpc.php'] as $endpoint => $name): ?>
    <details class="box-collapse hdn-endpoint-section u-mb20" id="hdn-endpoint-rate-<?= $endpoint ?>">
    <summary class="box-collapse-header"><?= $escape($name) ?></summary>
    <div class="box-collapse-content">
    <label class="form-label u-block u-mb10"><input form="hdn-settings" type="checkbox" name="<?= $endpoint ?>_enabled" <?= !empty($policy[$endpoint]['enabled']) ? 'checked' : '' ?>> Enabled</label>
    <label class="form-label" for="<?= $endpoint ?>-rate">Requests per minute, per client and domain</label>
    <input form="hdn-settings" class="form-control u-mb10" id="<?= $endpoint ?>-rate" type="number" min="1" name="<?= $endpoint ?>_rate" value="<?= $escape($policy[$endpoint]['rate'] ?? 5) ?>" required>
    <label class="form-label" for="<?= $endpoint ?>-burst">Burst allowance</label>
    <input form="hdn-settings" class="form-control u-mb20" id="<?= $endpoint ?>-burst" type="number" min="0" name="<?= $endpoint ?>_burst" value="<?= $escape($policy[$endpoint]['burst'] ?? 3) ?>" required>
    </div></details>
    <?php endforeach; ?>
