<?php
header('Content-Type: application/json');

function ini_bool(string $name): bool {
    $value = ini_get($name);
    return $value !== false && filter_var($value, FILTER_VALIDATE_BOOLEAN);
}

echo json_encode([
    'php' => [
        'version' => PHP_VERSION,
        'sapi' => PHP_SAPI,
        'zts' => PHP_ZTS === 1,
        'debug' => PHP_DEBUG === 1,
    ],
    'runtime' => [
        'mpm' => 'prefork',
        'workers' => 1,
        'memory_limit' => ini_get('memory_limit'),
        'post_max_size' => ini_get('post_max_size'),
        'upload_max_filesize' => ini_get('upload_max_filesize'),
        'max_input_vars' => (int) ini_get('max_input_vars'),
        'display_errors' => ini_bool('display_errors'),
        'file_uploads' => ini_bool('file_uploads'),
        'session_extension' => extension_loaded('session'),
        'upload_progress_enabled' => ini_bool('session.upload_progress.enabled'),
        'session_use_trans_sid' => ini_bool('session.use_trans_sid'),
        'session_use_cookies' => ini_bool('session.use_cookies'),
        'session_use_only_cookies' => ini_bool('session.use_only_cookies'),
        'upload_progress_cleanup' => ini_bool('session.upload_progress.cleanup'),
        'url_rewriter_tags' => ini_get('url_rewriter.tags'),
        'session_name' => ini_get('session.name'),
        'upload_progress_name' => ini_get('session.upload_progress.name'),
    ],
], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
