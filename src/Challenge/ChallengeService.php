<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Challenge;

use DateTimeImmutable;
use DateTimeZone;
use SzepeViktor\WordPress\Waf\Config;
use SzepeViktor\WordPress\Waf\Replay\ReplayStore;
use SzepeViktor\WordPress\Waf\Request;
use SzepeViktor\WordPress\Waf\Security\TokenService;

final class ChallengeService
{
    public function __construct(
        private readonly Config $config,
        private readonly TokenService $tokenService,
        private readonly ReplayStore $replayStore,
    ) {
    }

    public function create(Request $request, int $now): Challenge
    {
        $nonce = rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '=');
        $resource = $request->encodedResource();
        $expires = $now + $this->config->challengeTtl;

        return new Challenge(
            bits: $this->config->bits,
            ttl: $this->config->challengeTtl,
            resource: $resource,
            token: $this->tokenService->issueChallenge(
                host: $request->host,
                resource: $resource,
                bits: $this->config->bits,
                nonce: $nonce,
                expires: $expires,
            ),
        );
    }

    public function verify(Request $request, string $stamp, int $now): bool
    {
        $parts = explode(':', trim($stamp));
        if (count($parts) !== 7 || $parts[0] !== '1' || !ctype_digit($parts[1])) {
            return false;
        }

        if ((int) $parts[1] !== $this->config->bits) {
            return false;
        }

        $date = $this->parseDate($parts[2]);
        if ($date === null || abs($now - $date) > $this->config->challengeTtl) {
            return false;
        }

        $resource = $request->encodedResource();
        if (!hash_equals($resource, $parts[3])) {
            return false;
        }

        $challenge = $this->tokenService->validateChallenge(
            token: $parts[4],
            host: $request->host,
            resource: $resource,
            bits: $this->config->bits,
            now: $now,
            maximumTtl: $this->config->challengeTtl,
        );
        if (
            $challenge === null
            || $parts[5] === ''
            || $parts[6] === ''
        ) {
            return false;
        }

        if ($this->leadingZeroBits(sha1($stamp)) < $this->config->bits) {
            return false;
        }

        return $this->replayStore->claim($challenge['nonce'], $challenge['expires'], $now);
    }

    private function parseDate(string $date): ?int
    {
        if (strlen($date) !== 12 || !ctype_digit($date)) {
            return null;
        }

        $dateTime = DateTimeImmutable::createFromFormat('!ymdHis', $date, new DateTimeZone('UTC'));
        $errors = DateTimeImmutable::getLastErrors();
        if (
            $dateTime === false
            || ($errors !== false && ($errors['warning_count'] > 0 || $errors['error_count'] > 0))
            || $dateTime->format('ymdHis') !== $date
        ) {
            return null;
        }

        return $dateTime->getTimestamp();
    }

    private function leadingZeroBits(string $hex): int
    {
        $bits = 0;

        for ($index = 0, $length = strlen($hex); $index < $length; $index++) {
            $nibble = hexdec($hex[$index]);
            if ($nibble === 0) {
                $bits += 4;
                continue;
            }

            if ($nibble >= 8) {
                return $bits;
            }

            if ($nibble >= 4) {
                return $bits + 1;
            }

            if ($nibble >= 2) {
                return $bits + 2;
            }

            return $bits + 3;
        }

        return $bits;
    }
}
