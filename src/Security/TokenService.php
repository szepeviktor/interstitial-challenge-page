<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Security;

use JsonException;

final class TokenService
{
    private const MAX_LOGIN_ERROR_JSON_BYTES = 2800;

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

    public function issueAuthAssertion(string $host, string $wordpressCookie, int $expires): string
    {
        $binding = hash('sha256', $wordpressCookie);
        $signature = $this->sign('wordpress-auth', $host, $expires, $binding);

        return 'v1.' . $expires . '.' . $binding . '.' . $signature;
    }

    /**
     * @param array<string, list<string>> $messages
     */
    public function issueLoginError(string $host, array $messages, int $expires): ?string
    {
        try {
            $json = json_encode($messages, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException) {
            return null;
        }

        if (strlen($json) > self::MAX_LOGIN_ERROR_JSON_BYTES) {
            return null;
        }

        $payload = rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
        $signature = $this->sign('wordpress-login-error', $host, $expires, $payload);

        return 'v1.' . $expires . '.' . $payload . '.' . $signature;
    }

    /**
     * @return array<string, list<string>>|null
     */
    public function validateLoginError(
        string $token,
        string $host,
        int $now,
        int $maximumTtl,
    ): ?array {
        $parts = explode('.', $token);
        if (
            count($parts) !== 4
            || $parts[0] !== 'v1'
            || !ctype_digit($parts[1])
            || !preg_match('/^[A-Za-z0-9_-]+$/', $parts[2])
        ) {
            return null;
        }

        $expires = (int) $parts[1];
        if ($expires < $now || $expires > $now + $maximumTtl) {
            return null;
        }

        $expected = $this->sign('wordpress-login-error', $host, $expires, $parts[2]);
        if (!hash_equals($expected, $parts[3])) {
            return null;
        }

        $encoded = strtr($parts[2], '-_', '+/');
        $padding = strlen($encoded) % 4;
        if ($padding !== 0) {
            $encoded .= str_repeat('=', 4 - $padding);
        }

        $json = base64_decode($encoded, true);
        if ($json === false || strlen($json) > self::MAX_LOGIN_ERROR_JSON_BYTES) {
            return null;
        }

        try {
            $messages = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        if (!is_array($messages)) {
            return null;
        }

        $validated = [];
        foreach ($messages as $code => $codeMessages) {
            if (!is_string($code) || $code === '' || !is_array($codeMessages)) {
                return null;
            }

            foreach ($codeMessages as $message) {
                if (!is_string($message)) {
                    return null;
                }

                $validated[$code][] = $message;
            }
        }

        return $validated;
    }

    /**
     * @param list<string> $wordpressCookies
     */
    public function validateAuthAssertion(
        string $token,
        string $host,
        array $wordpressCookies,
        int $now,
        int $maximumTtl,
    ): bool {
        $parts = explode('.', $token);
        if (
            count($parts) !== 4
            || $parts[0] !== 'v1'
            || !ctype_digit($parts[1])
            || !preg_match('/^[a-f0-9]{64}$/', $parts[2])
        ) {
            return false;
        }

        $expires = (int) $parts[1];
        if ($expires < $now || $expires > $now + $maximumTtl) {
            return false;
        }

        $expected = $this->sign('wordpress-auth', $host, $expires, $parts[2]);
        if (!hash_equals($expected, $parts[3])) {
            return false;
        }

        foreach ($wordpressCookies as $wordpressCookie) {
            if (hash_equals($parts[2], hash('sha256', $wordpressCookie))) {
                return true;
            }
        }

        return false;
    }

    private function sign(string $purpose, string $host, int $expires, string $binding): string
    {
        $payload = implode('|', ['v1', $purpose, strtolower($host), (string) $expires, $binding]);
        return hash_hmac('sha256', $payload, $this->secret);
    }
}
