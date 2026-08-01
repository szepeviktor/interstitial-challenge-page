<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Scoring\Rules;

use SzepeViktor\WordPress\Waf\Request;
use SzepeViktor\WordPress\Waf\Scoring\Score;
use SzepeViktor\WordPress\Waf\Scoring\ScoringRule;

final class SuspiciousPathRule implements ScoringRule
{
    public const SCORE = 80;

    public function evaluate(Request $request): Score
    {
        $rawPath = strtolower($request->path);
        $decodedPath = strtolower(rawurldecode(rawurldecode($rawPath)));

        if (
            str_contains($rawPath, '%00')
            || str_contains($decodedPath, "\0")
            || preg_match('~(?:^|/)\.\.(?:/|$)~', $decodedPath) === 1
        ) {
            return new Score(self::SCORE, ['path_traversal_probe']);
        }

        if (
            preg_match(
                '~(?:^|/)(?:'
                . '\.env(?:[./]|$)|'
                . '\.git(?:/|$)|'
                . 'wp-config(?:\.php)?(?:[.\~_/-]|$)|'
                . 'wp-content/debug\.log$|'
                . 'vendor/phpunit(?:/|$)|'
                . 'phpinfo\.php$'
                . ')~',
                $decodedPath,
            ) === 1
        ) {
            return new Score(self::SCORE, ['sensitive_path_probe']);
        }

        return new Score(0);
    }
}
