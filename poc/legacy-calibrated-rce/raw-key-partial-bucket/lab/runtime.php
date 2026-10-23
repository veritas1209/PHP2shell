<?php
header('Content-Type: application/json');
echo json_encode([
    'php_version' => PHP_VERSION,
    'apache_version' => $_SERVER['SERVER_SOFTWARE'] ?? '',
    'sapi' => PHP_SAPI,
    'memory_limit' => ini_get('memory_limit'),
    'upload_progress_enabled' => ini_get('session.upload_progress.enabled'),
], JSON_UNESCAPED_SLASHES), "\n";
