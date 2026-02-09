<?php
// This is a clean PHP file with no suspicious patterns
function greet($name) {
    return "Hello, " . htmlspecialchars($name) . "!";
}

echo greet("World");
?>
