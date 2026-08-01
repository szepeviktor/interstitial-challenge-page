<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Scoring;

use SzepeViktor\WordPress\Waf\Request;

interface ScoringRule
{
    public function evaluate(Request $request): Score;
}
