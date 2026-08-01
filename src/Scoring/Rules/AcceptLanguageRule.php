<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Scoring\Rules;

use SzepeViktor\WordPress\Waf\Request;
use SzepeViktor\WordPress\Waf\Scoring\Score;
use SzepeViktor\WordPress\Waf\Scoring\ScoringRule;

final class AcceptLanguageRule implements ScoringRule
{
    public const MISSING_SCORE = 10;
    public const OVERSIZED_SCORE = 20;

    public function evaluate(Request $request): Score
    {
        $acceptLanguage = trim($request->header('accept-language'));

        if ($acceptLanguage === '') {
            return new Score(self::MISSING_SCORE, ['accept_language_missing']);
        }

        if (strlen($acceptLanguage) > 512) {
            return new Score(self::OVERSIZED_SCORE, ['accept_language_oversized']);
        }

        return new Score(0);
    }
}
