<?php
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $cache_freed = function_exists('gc_mem_caches') ? gc_mem_caches() : -1;
    header('Content-Type: application/json');
    echo json_encode([
        'pid' => getmypid(),
        'memory_limit' => ini_get('memory_limit'),
        'post_max_size' => ini_get('post_max_size'),
        'upload_max_filesize' => ini_get('upload_max_filesize'),
        'display_errors' => ini_get('display_errors'),
        'log_errors' => ini_get('log_errors'),
        'error_reporting' => error_reporting(),
        'session_use_cookies' => ini_get('session.use_cookies'),
        'session_use_only_cookies' => ini_get('session.use_only_cookies'),
        'session_use_trans_sid' => ini_get('session.use_trans_sid'),
        'gc_mem_caches_freed' => $cache_freed,
    ]), "\n";
}
