<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Scoring\Rules;

use SzepeViktor\WordPress\Waf\Request;
use SzepeViktor\WordPress\Waf\Scoring\Score;
use SzepeViktor\WordPress\Waf\Scoring\ScoringRule;

final class ChromeHttp11ConnectionRule implements ScoringRule
{
    public const SCORE = 20;

    /** @var list<string> */
    private const PROXY_HEADERS = [
        'forwarded',
        'x-forwarded-for',
        'x-forwarded-proto',
        'via',
        'cf-ray',
    ];

    public function evaluate(Request $request): Score
    {
        if (
            $request->protocol !== 'HTTP/1.1'
            || !$request->isHtmlDocumentNavigation()
            || preg_match('/\bChrome\/\d+/i', $request->header('user-agent')) !== 1
        ) {
            return new Score(0);
        }

        foreach (self::PROXY_HEADERS as $header) {
            if (trim($request->header($header)) !== '') {
                return new Score(0);
            }
        }

        if (strtolower(trim($request->header('connection'))) !== 'keep-alive') {
            return new Score(self::SCORE, ['chrome_http1_connection_unexpected']);
        }

        return new Score(0);
    }
}
