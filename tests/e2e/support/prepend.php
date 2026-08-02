<?php

declare(strict_types=1);

use SzepeViktor\WordPress\Waf\Config;
use SzepeViktor\WordPress\Waf\EarlyGate;
use SzepeViktor\WordPress\Waf\Replay\NullReplayStore;
use SzepeViktor\WordPress\Waf\Replay\RedisReplayStore;
use SzepeViktor\WordPress\Waf\Request;
use SzepeViktor\WordPress\Waf\Scoring\Score;
use SzepeViktor\WordPress\Waf\Scoring\Scorer;

if (PHP_SAPI !== 'cli-server' || defined('HC_E2E_PREPENDED')) {
    return;
}

define('HC_E2E_PREPENDED', true);

$repository = dirname(__DIR__, 3);
$host = (string) ($_SERVER['HTTP_HOST'] ?? 'localhost');
$fakeHttps = ($_SERVER['HTTP_X_HC_E2E_HTTPS'] ?? 'on') !== 'off';

if ($fakeHttps) {
    $_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
} else {
    unset($_SERVER['HTTP_X_FORWARDED_PROTO'], $_SERVER['HTTP_CF_VISITOR']);
}

defined('WP_HOME') || define('WP_HOME', 'http://' . $host);
defined('WP_SITEURL') || define('WP_SITEURL', 'http://' . $host);
defined('DISABLE_WP_CRON') || define('DISABLE_WP_CRON', true);
defined('WPMU_PLUGIN_DIR') || define('WPMU_PLUGIN_DIR', __DIR__ . '/mu-plugins');
defined('WPMU_PLUGIN_URL') || define('WPMU_PLUGIN_URL', 'http://' . $host . '/e2e-mu-plugins');

defined('HASHCASH_INTERSTITIAL_SECRET')
    || define('HASHCASH_INTERSTITIAL_SECRET', 'e2e-only-secret-with-at-least-32-bytes');
defined('HASHCASH_INTERSTITIAL_THRESHOLD') || define('HASHCASH_INTERSTITIAL_THRESHOLD', 50);
$bits = (int) (getenv('HC_E2E_BITS') ?: 8);
defined('HASHCASH_INTERSTITIAL_BITS') || define('HASHCASH_INTERSTITIAL_BITS', $bits);
defined('HASHCASH_INTERSTITIAL_CHALLENGE_TTL') || define('HASHCASH_INTERSTITIAL_CHALLENGE_TTL', 30);
defined('HASHCASH_INTERSTITIAL_CLEARANCE_TTL') || define('HASHCASH_INTERSTITIAL_CLEARANCE_TTL', 120);
defined('HASHCASH_INTERSTITIAL_AUTH_TTL') || define('HASHCASH_INTERSTITIAL_AUTH_TTL', 120);
$failOpen = ($_SERVER['HTTP_X_HC_E2E_FAIL_OPEN'] ?? '') === '1';
defined('HASHCASH_INTERSTITIAL_FAIL_OPEN') || define('HASHCASH_INTERSTITIAL_FAIL_OPEN', $failOpen);

require_once $repository . '/vendor/autoload.php';

$replayMode = (string) (getenv('HC_E2E_REPLAY_STORE') ?: 'redis');
$simulateGateFailure = ($_SERVER['HTTP_X_HC_E2E_GATE_FAILURE'] ?? '') === '1';
$scorer = $simulateGateFailure
    ? new class implements Scorer {
        public function score(Request $request): Score
        {
            throw new RuntimeException('Simulated scorer failure.');
        }
    }
    : null;

if ($replayMode === 'null') {
    $replayStore = new NullReplayStore();
} else {
    $simulateReplayFailure = ($_SERVER['HTTP_X_HC_E2E_REPLAY_FAILURE'] ?? '') === '1';
    $redis = $simulateReplayFailure
        ? new class extends Redis {
            public function set(string $key, mixed $value, mixed $options = null): Redis|string|bool
            {
                throw new RedisException('Simulated Redis SET failure.');
            }
        }
        : new Redis();

    if (!$simulateReplayFailure) {
        $redis->connect(
            (string) (getenv('HC_E2E_REDIS_HOST') ?: '127.0.0.1'),
            (int) (getenv('HC_E2E_REDIS_PORT') ?: 6379),
            1.0,
        );
    }

    $runId = preg_replace('/[^a-z0-9_-]/i', '', (string) getenv('HC_E2E_RUN_ID')) ?: 'default';
    $replayStore = new RedisReplayStore($redis, 'hashcash-e2e:' . $runId . ':');
}

(new EarlyGate(
    config: Config::fromConstants(),
    scorer: $scorer,
    replayStore: $replayStore,
))->run();
