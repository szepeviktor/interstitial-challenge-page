<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Scoring;

use SzepeViktor\WordPress\Waf\Request;

final class RuleBasedScorer implements Scorer
{
    /**
     * @param list<ScoringRule> $rules
     */
    public function __construct(private readonly array $rules)
    {
    }

    public function score(Request $request): Score
    {
        $value = 0;
        $reasons = [];

        foreach ($this->rules as $rule) {
            $contribution = $rule->evaluate($request);
            $value += $contribution->value;
            array_push($reasons, ...$contribution->reasons);
        }

        return new Score(min($value, 100), array_values(array_unique($reasons)));
    }
}
