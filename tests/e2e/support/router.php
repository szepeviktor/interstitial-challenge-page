<?php

declare(strict_types=1);

require_once __DIR__ . '/prepend.php';

$wordpress = rtrim(
    (string) (getenv('HC_E2E_WORDPRESS_PATH') ?: '/home/viktor/chatgpt-is-super'),
    '/',
);
$path = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
$path = is_string($path) ? rawurldecode($path) : '/';
$candidate = realpath($wordpress . '/' . ltrim($path, '/'));

if ($candidate !== false && str_starts_with($candidate, $wordpress . '/')) {
    if (is_dir($candidate) && is_file($candidate . '/index.php')) {
        $candidate .= '/index.php';
    }

    if (is_file($candidate)) {
        if (pathinfo($candidate, PATHINFO_EXTENSION) !== 'php') {
            return false;
        }

        $_SERVER['SCRIPT_FILENAME'] = $candidate;
        $_SERVER['SCRIPT_NAME'] = $path;
        $_SERVER['PHP_SELF'] = $path;

        chdir(dirname($candidate));
        require $candidate;
        return true;
    }
}

$_SERVER['SCRIPT_FILENAME'] = $wordpress . '/index.php';
$_SERVER['SCRIPT_NAME'] = '/index.php';
$_SERVER['PHP_SELF'] = '/index.php';

chdir($wordpress);
require $wordpress . '/index.php';
