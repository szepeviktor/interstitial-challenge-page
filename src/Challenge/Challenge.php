<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Challenge;

final class Challenge
{
    public function __construct(
        public readonly int $bits,
        public readonly int $ttl,
        public readonly string $resource,
        public readonly string $token,
    ) {
    }
}
