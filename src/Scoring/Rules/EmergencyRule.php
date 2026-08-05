<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Scoring\Rules;

use SzepeViktor\WordPress\Waf\Request;
use SzepeViktor\WordPress\Waf\Scoring\Score;
use SzepeViktor\WordPress\Waf\Scoring\ScoringRule;

final class EmergencyRule implements ScoringRule
{
    /**
     * @param list<array{type: string, score: int, reason: string, value?: string, name?: string}> $rules
     */
    public function __construct(private readonly array $rules)
    {
    }

    public function evaluate(Request $request): Score
    {
        $value = 0;
        $reasons = [];

        foreach ($this->rules as $rule) {
            if (!$this->matches($rule, $request)) {
                continue;
            }

            $value += $rule['score'];
            $reasons[] = $rule['reason'];
        }

        return new Score(min($value, 100), array_values(array_unique($reasons)));
    }

    /**
     * @param array{type: string, score: int, reason: string, value?: string, name?: string} $rule
     */
    private function matches(array $rule, Request $request): bool
    {
        $value = $rule['value'] ?? '';

        return match ($rule['type']) {
            'path_exact' => $request->path === $value,
            'path_prefix' => str_starts_with($request->path, $value),
            'path_contains' => str_contains($request->path, $value),
            'path_regex' => preg_match($value, $request->path) === 1,
            'method' => $request->method === $value,
            'method_path' => $request->method . ' ' . $request->path === $value,
            'header_missing' => $request->header((string) $rule['name']) === '',
            'header_equals' => $request->header((string) $rule['name']) === $value,
            'header_contains' => stripos($request->header((string) $rule['name']), $value) !== false,
            'header_regex' => preg_match($value, $request->header((string) $rule['name'])) === 1,
            'ip_exact' => $this->sameIp($request->clientIp, $value),
            'ip_cidr' => $this->ipInCidr($request->clientIp, $value),
            default => false,
        };
    }

    private function sameIp(string $ip, string $expected): bool
    {
        $packedIp = @inet_pton($ip);
        $packedExpected = @inet_pton($expected);

        return $packedIp !== false && $packedIp === $packedExpected;
    }

    private function ipInCidr(string $ip, string $cidr): bool
    {
        [$range, $prefix] = explode('/', $cidr, 2);
        $packedIp = @inet_pton($ip);
        $packedRange = @inet_pton($range);

        if ($packedIp === false || $packedRange === false || strlen($packedIp) !== strlen($packedRange)) {
            return false;
        }

        $bits = (int) $prefix;
        $maxBits = strlen($packedIp) * 8;
        if ($bits < 0 || $bits > $maxBits) {
            return false;
        }

        $bytes = intdiv($bits, 8);
        $remainingBits = $bits % 8;

        if ($bytes > 0 && substr($packedIp, 0, $bytes) !== substr($packedRange, 0, $bytes)) {
            return false;
        }

        if ($remainingBits === 0) {
            return true;
        }

        $mask = 0xff << (8 - $remainingBits) & 0xff;
        return (ord($packedIp[$bytes]) & $mask) === (ord($packedRange[$bytes]) & $mask);
    }
}
