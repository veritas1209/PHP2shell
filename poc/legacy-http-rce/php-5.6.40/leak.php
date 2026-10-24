<?php
ob_implicit_flush(true);
$v = $_POST['PHP_SESSION_UPLOAD_PROGRESS'];
echo 'PROGRESSHEX:', bin2hex($v), "\n";
flush();
