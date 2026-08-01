<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Scoring;

use SzepeViktor\WordPress\Waf\Request;

final class NullScorer implements Scorer
{
    public function score(Request $request): Score
    {
        return new Score(0);
    }
}
