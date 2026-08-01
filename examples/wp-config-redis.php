<?php

/*
 * Place this before wp-settings.php is required. Generate a unique secret for
 * each site; do not reuse AUTH_SALT or another WordPress authentication key.
 */
define(
    'HASHCASH_INTERSTITIAL_SECRET',
    'replace-with-at-least-32-cryptographically-random-bytes',
);

require_once __DIR__ . '/vendor/autoload.php';

/*
 * The Redis connection must be available before WordPress boots.
 */
$redis = new Redis();
$redis->connect('127.0.0.1', 6379, 0.25);

(new SzepeViktor\WordPress\Waf\EarlyGate(
    SzepeViktor\WordPress\Waf\Config::fromConstants(),
    replayStore: new SzepeViktor\WordPress\Waf\Replay\RedisReplayStore($redis),
))->run();
