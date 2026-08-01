<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Scoring\Rules;

use SzepeViktor\WordPress\Waf\Request;
use SzepeViktor\WordPress\Waf\Scoring\Score;
use SzepeViktor\WordPress\Waf\Scoring\ScoringRule;

final class UserAgentRule implements ScoringRule
{
    public const MISSING_SCORE = 60;
    public const SCRIPTED_CLIENT_SCORE = 60;
    public const OVERSIZED_SCORE = 30;

    public function evaluate(Request $request): Score
    {
        $userAgent = trim($request->header('user-agent'));

        if ($userAgent === '') {
            return new Score(self::MISSING_SCORE, ['user_agent_missing']);
        }

        if (strlen($userAgent) > 1024) {
            return new Score(self::OVERSIZED_SCORE, ['user_agent_oversized']);
        }

        if (
            preg_match(
                '/(?:\bcurl\/|\bwget\/|python-requests\/|python-urllib\/|'
                . 'go-http-client\/|libwww-perl\/|scrapy\/|aiohttp\/|httpx\/)/i',
                $userAgent,
            ) === 1
        ) {
            return new Score(self::SCRIPTED_CLIENT_SCORE, ['user_agent_scripted_client']);
        }

        return new Score(0);
    }
}
