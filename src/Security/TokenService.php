<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Security;

final class TokenService
{
    public function __construct(private readonly string $secret)
    {
    }

    public function issueClearance(string $host, int $expires): string
    {
        $signature = $this->sign('clearance', $host, $expires, '');
        return 'v1.' . $expires . '.' . $signature;
    }

    public function issueChallenge(
        string $host,
        string $resource,
        int $bits,
        string $nonce,
        int $expires,
    ): string {
        $binding = $bits . '|' . $resource . '|' . $nonce;
        $signature = $this->sign('challenge', $host, $expires, $binding);

        return 'v1.' . $expires . '.' . $nonce . '.' . $signature;
    }

    /**
     * @return array{nonce: string, expires: int}|null
     */
    public function validateChallenge(
        string $token,
        string $host,
        string $resource,
        int $bits,
        int $now,
        int $maximumTtl,
    ): ?array {
        $parts = explode('.', $token);
        if (
            count($parts) !== 4
            || $parts[0] !== 'v1'
            || !ctype_digit($parts[1])
            || !preg_match('/^[A-Za-z0-9_-]{24}$/', $parts[2])
        ) {
            return null;
        }

        $expires = (int) $parts[1];
        if ($expires < $now || $expires > $now + $maximumTtl) {
            return null;
        }

        $binding = $bits . '|' . $resource . '|' . $parts[2];
        if (!hash_equals($this->sign('challenge', $host, $expires, $binding), $parts[3])) {
            return null;
        }

        return ['nonce' => $parts[2], 'expires' => $expires];
    }

    public function validateClearance(
        string $token,
        string $host,
        int $now,
        int $maximumTtl,
    ): bool {
        $parts = explode('.', $token);
        if (count($parts) !== 3 || $parts[0] !== 'v1' || !ctype_digit($parts[1])) {
            return false;
        }

        $expires = (int) $parts[1];
        if ($expires < $now || $expires > $now + $maximumTtl) {
            return false;
        }

        return hash_equals($this->sign('clearance', $host, $expires, ''), $parts[2]);
    }

    private function sign(string $purpose, string $host, int $expires, string $binding): string
    {
        $payload = implode('|', ['v1', $purpose, strtolower($host), (string) $expires, $binding]);
        return hash_hmac('sha256', $payload, $this->secret);
    }
}
