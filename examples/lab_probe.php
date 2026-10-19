<?php
declare(strict_types=1);

/*
 * STIS SOC lab-only event generator. It performs no login or database query.
 * Deploy only in the isolated web1 lab. A private token authorizes each POST;
 * the endpoint never performs a login or database operation.
 */

header('Content-Type: text/plain; charset=UTF-8');

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(404);
    exit;
}

$tokenFile = '/etc/stis-soc-lab/probe-token';
$expected = @file_get_contents($tokenFile);
$supplied = $_SERVER['HTTP_X_STIS_SOC_LAB_TOKEN'] ?? '';
if ($expected === false || trim($expected) === '' || !is_string($supplied) ||
    !hash_equals(trim($expected), $supplied)) {
    http_response_code(404);
    exit;
}

$sourceIp = $_SERVER['REMOTE_ADDR'] ?? '';
if (!filter_var($sourceIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    http_response_code(400);
    echo "Invalid source IP\n";
    exit;
}

$mode = $_POST['mode'] ?? '';
$username = substr((string) ($_POST['username'] ?? 'lab-user'), 0, 80);
$username = preg_replace('/[^A-Za-z0-9_.@-]/', '_', $username);
$eventType = null;

if ($mode === 'auth-failed') {
    // The helper deliberately has no real account or password check.
    $eventType = 'stis_auth_failed';
    $status = 401;
} elseif ($mode === 'sqli') {
    // Require a recognizable *test* pattern; no input reaches a database.
    if (!preg_match('/(?:\bunion\s+select\b|\binformation_schema\b|\bor\s+[\'\"]?1[\'\"]?\s*=\s*[\'\"]?1)/i',
                    (string) ($_POST['username'] ?? ''))) {
        http_response_code(400);
        echo "Test pattern missing\n";
        exit;
    }
    $eventType = 'stis_sqli_attempt';
    $status = 403;
} else {
    http_response_code(400);
    echo "Unknown test mode\n";
    exit;
}

$event = [
    'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
    'event_type' => $eventType,
    'srcip' => $sourceIp,
    'dstuser' => $username,
    'url' => '/lab_probe.php',
    'domain' => 'web1.stis.local',
    'asset_name' => 'web1',
];
$encoded = json_encode($event, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
$logFile = '/var/log/stis-soc/apps/web1.jsonl';
if ($encoded === false || @file_put_contents($logFile, $encoded . "\n", FILE_APPEND | LOCK_EX) === false) {
    error_log('STIS SOC lab probe could not write event log');
    http_response_code(503);
    echo "Lab event log unavailable\n";
    exit;
}

http_response_code($status);
echo $mode === 'auth-failed' ? "Lab login denied\n" : "Lab SQLi input rejected\n";
