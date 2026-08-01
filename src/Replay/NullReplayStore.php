<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Replay;

final class NullReplayStore implements ReplayStore
{
    public function claim(string $nonce, int $expires, int $now): bool
    {
        return true;
    }
}
