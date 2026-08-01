<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Replay;

interface ReplayStore
{
    public function claim(string $nonce, int $expires, int $now): bool;
}
