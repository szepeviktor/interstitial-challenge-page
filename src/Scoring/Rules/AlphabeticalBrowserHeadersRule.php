<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Scoring\Rules;

use SzepeViktor\WordPress\Waf\Request;
use SzepeViktor\WordPress\Waf\Scoring\Score;
use SzepeViktor\WordPress\Waf\Scoring\ScoringRule;

final class AlphabeticalBrowserHeadersRule implements ScoringRule
{
    public const SCORE = 30;

    /**
     * Proxy-specific headers are deliberately absent: their insertion must not
     * hide an alphabetically generated browser-header block.
     *
     * @var list<string>
     */
    private const BROWSER_HEADERS = [
        'accept',
        'accept-encoding',
        'accept-language',
        'cache-control',
        'host',
        'referer',
        'sec-ch-ua',
        'sec-ch-ua-mobile',
        'sec-ch-ua-platform',
        'sec-fetch-dest',
        'sec-fetch-mode',
        'sec-fetch-site',
        'sec-fetch-user',
        'upgrade-insecure-requests',
        'user-agent',
    ];

    private const MINIMUM_HEADERS = 10;

    public function evaluate(Request $request): Score
    {
        if (!$request->isHtmlDocumentNavigation()) {
            return new Score(0);
        }

        $browserHeaders = [];
        foreach (array_keys($request->headers) as $name) {
            if (in_array($name, self::BROWSER_HEADERS, true)) {
                $browserHeaders[] = $name;
            }
        }

        if (count($browserHeaders) < self::MINIMUM_HEADERS) {
            return new Score(0);
        }

        $sortedHeaders = $browserHeaders;
        sort($sortedHeaders, SORT_STRING);

        if ($browserHeaders === $sortedHeaders) {
            return new Score(self::SCORE, ['browser_headers_alphabetical']);
        }

        return new Score(0);
    }
}
