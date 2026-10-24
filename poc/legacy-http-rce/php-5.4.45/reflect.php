<?php
/*
 * Bounded request-state reflector for the local PHP 5.4 allocator lab.
 * It deliberately avoids session_start(): the goal is to inspect the
 * request parser's own POST/COOKIE strings after the multipart callback.
 */
header('Content-Type: text/plain');

function edge_hex($value, $tail) {
    $length = strlen($value);
    if ($tail && $length > 64) {
        return bin2hex(substr($value, $length - 64, 64));
    }
    return bin2hex(substr($value, 0, 64));
}

function emit_scope($scope, $values) {
    echo "SCOPE\t", $scope, "\tCOUNT\t", count($values), "\n";
    $index = 0;
    foreach ($values as $key => $value) {
        if ($index >= 160) {
            echo "TRUNCATED\t", $scope, "\n";
            break;
        }
        $key_string = (string) $key;
        echo "ENTRY\t", $scope,
             "\t", $index,
             "\tKLEN\t", strlen($key_string),
             "\tKHEAD\t", edge_hex($key_string, false),
             "\tKTAIL\t", edge_hex($key_string, true),
             "\tTYPE\t", gettype($value);
        if (is_string($value)) {
            echo "\tVLEN\t", strlen($value),
                 "\tVHEAD\t", edge_hex($value, false),
                 "\tVTAIL\t", edge_hex($value, true);
        }
        echo "\n";
        $index++;
    }
}

emit_scope('POST', $_POST);
emit_scope('COOKIE', $_COOKIE);
echo "DONE\n";
