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
     * @var list<array{type: string, score: int, reason: string, value?: string, name?: string}>
     */
    public readonly array $emergencyRules;

    /**
     * @param list<mixed> $requiredClearancePaths
     * @param list<mixed> $emergencyRules
     */
    public function __construct(
        public readonly string $secret,
        public readonly int $challengeThreshold = 50,
        public readonly int $bits = 20,
        public readonly int $challengeTtl = 30,
        public readonly int $clearanceTtl = 900,
        public readonly string $clearanceCookie = 'hc_clearance',
        public readonly bool $failOpen = true,
        public readonly ?string $logPath = null,
        array $requiredClearancePaths = [
            '/checkout',
            '/checkout/',
            '/wp-login.php',
        ],
        array $emergencyRules = [],
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

        if ($this->challengeTtl < 1 || $this->clearanceTtl < 1) {
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
        $this->emergencyRules = self::validateEmergencyRules($emergencyRules);
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
            failOpen: self::constantBool('HASHCASH_INTERSTITIAL_FAIL_OPEN', true),
            logPath: self::constantString('HASHCASH_INTERSTITIAL_LOG'),
            requiredClearancePaths: self::constantStringList(
                'HASHCASH_INTERSTITIAL_REQUIRED_PATHS',
                ['/checkout', '/checkout/', '/wp-login.php'],
            ),
            emergencyRules: self::constantEmergencyRules(),
        );
    }

    /**
     * @param list<mixed> $rules
     *
     * @return list<array{type: string, score: int, reason: string, value?: string, name?: string}>
     */
    private static function validateEmergencyRules(array $rules): array
    {
        $validated = [];

        foreach ($rules as $index => $rule) {
            if (!is_array($rule)) {
                throw new InvalidArgumentException('Emergency rule #' . $index . ' must be an array.');
            }

            $type = $rule['type'] ?? null;
            if (!is_string($type) || $type === '') {
                throw new InvalidArgumentException('Emergency rule #' . $index . ' must define a type.');
            }

            $score = $rule['score'] ?? null;
            if (!is_int($score) || $score < 0 || $score > 100) {
                throw new InvalidArgumentException('Emergency rule #' . $index . ' score must be an integer from 0 to 100.');
            }

            $reason = $rule['reason'] ?? 'emergency_' . $type;
            if (!is_string($reason) || $reason === '') {
                throw new InvalidArgumentException('Emergency rule #' . $index . ' reason must be a non-empty string.');
            }

            $normalized = [
                'type' => $type,
                'score' => $score,
                'reason' => $reason,
            ];

            if (in_array($type, ['header_missing', 'header_equals', 'header_contains', 'header_regex'], true)) {
                $name = $rule['name'] ?? null;
                if (!is_string($name) || !preg_match('/^[a-z0-9][a-z0-9_-]*$/i', $name)) {
                    throw new InvalidArgumentException('Emergency rule #' . $index . ' header name is invalid.');
                }

                $normalized['name'] = strtolower(str_replace('_', '-', $name));
            }

            if ($type !== 'header_missing') {
                $value = $rule['value'] ?? null;
                if (!is_string($value) || $value === '') {
                    throw new InvalidArgumentException('Emergency rule #' . $index . ' value must be a non-empty string.');
                }

                $normalized['value'] = $type === 'method' ? strtoupper($value) : $value;
            }

            self::validateEmergencyRuleValue($index, $normalized);
            $validated[] = $normalized;
        }

        return $validated;
    }

    /**
     * @param array{type: string, score: int, reason: string, value?: string, name?: string} $rule
     */
    private static function validateEmergencyRuleValue(int $index, array $rule): void
    {
        $type = $rule['type'];
        $value = $rule['value'] ?? '';

        if (!in_array($type, [
            'path_exact',
            'path_prefix',
            'path_contains',
            'path_regex',
            'method',
            'method_path',
            'header_missing',
            'header_equals',
            'header_contains',
            'header_regex',
            'header_names_equals',
            'ip_exact',
            'ip_cidr',
        ], true)) {
            throw new InvalidArgumentException('Emergency rule #' . $index . ' has an unsupported type.');
        }

        if (in_array($type, ['path_exact', 'path_prefix'], true) && $value[0] !== '/') {
            throw new InvalidArgumentException('Emergency rule #' . $index . ' path value must start with /.');
        }

        if ($type === 'path_regex' || $type === 'header_regex') {
            if (@preg_match($value, '') === false) {
                throw new InvalidArgumentException('Emergency rule #' . $index . ' regex is invalid.');
            }
        }

        if ($type === 'method' && !preg_match('/^[A-Z]+$/', $value)) {
            throw new InvalidArgumentException('Emergency rule #' . $index . ' method value is invalid.');
        }

        if ($type === 'method_path' && !preg_match('/^[A-Z]+ \//', $value)) {
            throw new InvalidArgumentException('Emergency rule #' . $index . ' method_path value must look like "POST /path".');
        }

        if ($type === 'ip_exact' && filter_var($value, FILTER_VALIDATE_IP) === false) {
            throw new InvalidArgumentException('Emergency rule #' . $index . ' IP address is invalid.');
        }

        if ($type === 'ip_cidr') {
            if (!preg_match('~^([^/]+)/(\d{1,3})$~', $value, $matches)) {
                throw new InvalidArgumentException('Emergency rule #' . $index . ' CIDR range is invalid.');
            }

            $packed = @inet_pton($matches[1]);
            if ($packed === false) {
                throw new InvalidArgumentException('Emergency rule #' . $index . ' CIDR range is invalid.');
            }

            $bits = (int) $matches[2];
            if ($bits < 0 || $bits > strlen($packed) * 8) {
                throw new InvalidArgumentException('Emergency rule #' . $index . ' CIDR range is invalid.');
            }
        }
    }

    /**
     * @return list<mixed>
     */
    private static function constantArray(string $name): array
    {
        if (!defined($name)) {
            return [];
        }

        $value = constant($name);
        if (!is_array($value)) {
            throw new InvalidArgumentException($name . ' must be an array.');
        }

        return array_values($value);
    }

    /**
     * @return list<array{type: string, score: int, reason: string, value?: string, name?: string}>
     */
    private static function constantEmergencyRules(): array
    {
        try {
            return self::validateEmergencyRules(self::constantArray('HASHCASH_INTERSTITIAL_EMERGENCY_RULES'));
        } catch (InvalidArgumentException $exception) {
            error_log('WordPress WAF emergency rules ignored: ' . $exception->getMessage());
            return [];
        }
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
