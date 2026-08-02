<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf;

use InvalidArgumentException;

final class Config
{
    /**
     * @var list<string>
     */
    public readonly array $requiredClearancePaths;

    /**
     * @param list<mixed> $requiredClearancePaths
     */
    public function __construct(
        public readonly string $secret,
        public readonly int $challengeThreshold = 50,
        public readonly int $bits = 20,
        public readonly int $challengeTtl = 30,
        public readonly int $clearanceTtl = 900,
        public readonly int $authAssertionTtl = 600,
        public readonly string $clearanceCookie = 'hc_clearance',
        public readonly string $authCookie = 'hc_wp_auth',
        public readonly bool $failOpen = true,
        public readonly ?string $logPath = null,
        array $requiredClearancePaths = [
            '/checkout',
            '/checkout/',
            '/wp-login.php',
        ],
    ) {
        if (strlen($this->secret) < 32) {
            throw new InvalidArgumentException('The WAF secret must contain at least 32 bytes.');
        }

        if ($this->challengeThreshold < 0 || $this->challengeThreshold > 100) {
            throw new InvalidArgumentException('The challenge threshold must be between 0 and 100.');
        }

        if ($this->bits < 1 || $this->bits > 30) {
            throw new InvalidArgumentException('Hashcash difficulty must be between 1 and 30 bits.');
        }

        if ($this->challengeTtl < 1 || $this->clearanceTtl < 1 || $this->authAssertionTtl < 1) {
            throw new InvalidArgumentException('Token lifetimes must be positive.');
        }

        if ($this->logPath !== null && trim($this->logPath) === '') {
            throw new InvalidArgumentException('The request-header log path must not be empty.');
        }

        $validatedPaths = [];
        foreach ($requiredClearancePaths as $path) {
            if (
                !is_string($path)
                || $path === ''
                || $path[0] !== '/'
                || str_contains($path, '?')
                || str_contains($path, '#')
            ) {
                throw new InvalidArgumentException(
                    'Required-clearance paths must be absolute paths without a query or fragment.',
                );
            }

            $validatedPaths[] = $path;
        }

        if (count(array_unique($validatedPaths)) !== count($validatedPaths)) {
            throw new InvalidArgumentException('Required-clearance paths must be unique.');
        }

        $this->requiredClearancePaths = $validatedPaths;
    }

    public static function fromConstants(): self
    {
        $secret = self::constantString('HASHCASH_INTERSTITIAL_SECRET') ?? '';

        return new self(
            secret: $secret,
            challengeThreshold: self::constantInt('HASHCASH_INTERSTITIAL_THRESHOLD', 50),
            bits: self::constantInt('HASHCASH_INTERSTITIAL_BITS', 20),
            challengeTtl: self::constantInt('HASHCASH_INTERSTITIAL_CHALLENGE_TTL', 30),
            clearanceTtl: self::constantInt('HASHCASH_INTERSTITIAL_CLEARANCE_TTL', 900),
            authAssertionTtl: self::constantInt('HASHCASH_INTERSTITIAL_AUTH_TTL', 600),
            failOpen: self::constantBool('HASHCASH_INTERSTITIAL_FAIL_OPEN', true),
            logPath: self::constantString('HASHCASH_INTERSTITIAL_LOG'),
            requiredClearancePaths: self::constantStringList(
                'HASHCASH_INTERSTITIAL_REQUIRED_PATHS',
                ['/checkout', '/checkout/', '/wp-login.php'],
            ),
        );
    }

    private static function constantString(string $name): ?string
    {
        if (!defined($name)) {
            return null;
        }

        $value = constant($name);
        return is_string($value) ? $value : null;
    }

    private static function constantInt(string $name, int $default): int
    {
        if (!defined($name)) {
            return $default;
        }

        return (int) constant($name);
    }

    private static function constantBool(string $name, bool $default): bool
    {
        if (!defined($name)) {
            return $default;
        }

        return (bool) constant($name);
    }

    /**
     * @param list<string> $default
     *
     * @return list<string>
     */
    private static function constantStringList(string $name, array $default): array
    {
        if (!defined($name)) {
            return $default;
        }

        $value = constant($name);
        if (!is_array($value)) {
            throw new InvalidArgumentException($name . ' must be an array of paths.');
        }

        return array_values($value);
    }
}
