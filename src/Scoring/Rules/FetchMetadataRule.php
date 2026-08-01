<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Scoring\Rules;

use SzepeViktor\WordPress\Waf\Request;
use SzepeViktor\WordPress\Waf\Scoring\Score;
use SzepeViktor\WordPress\Waf\Scoring\ScoringRule;

final class FetchMetadataRule implements ScoringRule
{
    public const INCONSISTENT_SCORE = 50;
    public const INCOMPLETE_SCORE = 15;

    public function evaluate(Request $request): Score
    {
        $destination = strtolower(trim($request->header('sec-fetch-dest')));
        $mode = strtolower(trim($request->header('sec-fetch-mode')));
        $site = strtolower(trim($request->header('sec-fetch-site')));
        $user = strtolower(trim($request->header('sec-fetch-user')));

        if ($destination === '' && $mode === '' && $site === '' && $user === '') {
            return new Score(0);
        }

        if (
            ($destination !== '' && $destination !== 'document')
            || ($mode !== '' && $mode !== 'navigate')
            || ($site !== '' && !in_array($site, ['none', 'same-origin', 'same-site', 'cross-site'], true))
            || ($user !== '' && $user !== '?1')
        ) {
            return new Score(self::INCONSISTENT_SCORE, ['fetch_metadata_inconsistent']);
        }

        if ($destination === '' || $mode === '' || $site === '') {
            return new Score(self::INCOMPLETE_SCORE, ['fetch_metadata_incomplete']);
        }

        return new Score(0);
    }
}
