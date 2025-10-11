<?php
// ONLY FOR LOCAL TESTING
$input = $_GET['q'] ?? '';
?>
<!DOCTYPE html>
<html>
<head><title>XSS Test Page</title></head>
<body>
    <p>You searched for: <?= $input ?></p>
</body>
</html>

