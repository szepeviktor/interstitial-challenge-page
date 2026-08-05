<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Scoring;

use SzepeViktor\WordPress\Waf\Config;
use SzepeViktor\WordPress\Waf\Request;
use SzepeViktor\WordPress\Waf\Scoring\Rules\AlphabeticalBrowserHeadersRule;
use SzepeViktor\WordPress\Waf\Scoring\Rules\AcceptLanguageRule;
use SzepeViktor\WordPress\Waf\Scoring\Rules\ChromeHttp11ConnectionRule;
use SzepeViktor\WordPress\Waf\Scoring\Rules\EmergencyRule;
use SzepeViktor\WordPress\Waf\Scoring\Rules\FetchMetadataRule;
use SzepeViktor\WordPress\Waf\Scoring\Rules\SuspiciousPathRule;
use SzepeViktor\WordPress\Waf\Scoring\Rules\UserAgentRule;

final class DefaultScorer implements Scorer
{
    private readonly RuleBasedScorer $scorer;

    public function __construct(?Config $config = null)
    {
        $rules = [
            new UserAgentRule(),
            new AcceptLanguageRule(),
            new FetchMetadataRule(),
            new AlphabeticalBrowserHeadersRule(),
            new ChromeHttp11ConnectionRule(),
            new SuspiciousPathRule(),
        ];

        if ($config !== null && $config->emergencyRules !== []) {
            $rules[] = new EmergencyRule($config->emergencyRules);
        }

        $this->scorer = new RuleBasedScorer($rules);
    }

    public function score(Request $request): Score
    {
        return $this->scorer->score($request);
    }
}
