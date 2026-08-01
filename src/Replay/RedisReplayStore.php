<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Replay;

use InvalidArgumentException;
use Redis;
use RedisCluster;

final class RedisReplayStore implements ReplayStore
{
    public function __construct(
        private readonly Redis|RedisCluster $redis,
        private readonly string $keyPrefix = 'wordpress-waf:proof:',
    ) {
    }

    public function claim(string $nonce, int $expires, int $now): bool
    {
        $ttl = $expires - $now;
        if ($ttl < 1) {
            return false;
        }

        $key = $this->keyPrefix . hash('sha256', $nonce);
        $result = $this->redis->set($key, '1', ['nx', 'ex' => $ttl]);

        if ($result === true || $result === 'OK') {
            return true;
        }

        if ($result === false) {
            return false;
        }

        throw new InvalidArgumentException('The Redis client returned an unexpected SET result.');
    }
}
