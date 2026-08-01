<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Scoring;

use InvalidArgumentException;

final class Score
{
    /**
     * @param list<string> $reasons
     */
    public function __construct(
        public readonly int $value,
        public readonly array $reasons = [],
    ) {
        if ($this->value < 0 || $this->value > 100) {
            throw new InvalidArgumentException('A request score must be between 0 and 100.');
        }
    }
}
