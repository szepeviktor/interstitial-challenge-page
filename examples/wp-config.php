<?php

/*
 * Place this before wp-settings.php is required. The package's default
 * scoring rules are used here. Generate a unique secret for each site.
 */
define(
    'HASHCASH_INTERSTITIAL_SECRET',
    'replace-with-at-least-32-cryptographically-random-bytes',
);

require_once __DIR__ . '/vendor/autoload.php';

(new SzepeViktor\WordPress\Waf\EarlyGate(
    SzepeViktor\WordPress\Waf\Config::fromConstants(),
    replayStore: new SzepeViktor\WordPress\Waf\Replay\NullReplayStore(),
))->run();
