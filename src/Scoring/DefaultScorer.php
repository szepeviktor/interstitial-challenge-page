<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Scoring;

use SzepeViktor\WordPress\Waf\Request;
use SzepeViktor\WordPress\Waf\Scoring\Rules\AcceptLanguageRule;
use SzepeViktor\WordPress\Waf\Scoring\Rules\FetchMetadataRule;
use SzepeViktor\WordPress\Waf\Scoring\Rules\SuspiciousPathRule;
use SzepeViktor\WordPress\Waf\Scoring\Rules\UserAgentRule;

final class DefaultScorer implements Scorer
{
    private readonly RuleBasedScorer $scorer;

    public function __construct()
    {
        $this->scorer = new RuleBasedScorer([
            new UserAgentRule(),
            new AcceptLanguageRule(),
            new FetchMetadataRule(),
            new SuspiciousPathRule(),
        ]);
    }

    public function score(Request $request): Score
    {
        return $this->scorer->score($request);
    }
}
