<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Logging;

use JsonException;
use SzepeViktor\WordPress\Waf\Request;
use SzepeViktor\WordPress\Waf\Scoring\Score;

final class RequestHeaderLogger
{
    private const MINIMUM_SCORE = 30;
    private const MAXIMUM_SCORE = 49;
    private const MAXIMUM_VALUE_LENGTH = 2048;

    /** @var list<string> */
    private const LOGGED_HEADERS = [
        'host',
        'user-agent',
        'accept',
        'accept-language',
        'sec-fetch-dest',
        'sec-fetch-mode',
        'sec-fetch-site',
        'sec-fetch-user',
        'x-forwarded-proto',
        'cf-ray',
    ];

    public function __construct(private readonly ?string $path)
    {
    }

    public function log(Request $request, Score $score): void
    {
        if (
            $this->path === null
            || $score->value < self::MINIMUM_SCORE
            || $score->value > self::MAXIMUM_SCORE
        ) {
            return;
        }

        $headers = [];
        foreach (self::LOGGED_HEADERS as $name) {
            $value = $request->header($name);
            if ($value !== '') {
                $headers[$name] = $this->sanitize($value);
            }
        }

        try {
            $line = json_encode(
                [
                    'timestamp' => gmdate('c'),
                    'method' => $request->method,
                    'host' => $request->host,
                    'target' => $this->sanitize($request->target),
                    'score' => $score->value,
                    'reasons' => $score->reasons,
                    'headers' => $headers,
                ],
                JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE,
            );
        } catch (JsonException $exception) {
            error_log('Hashcash request-header logging failed: ' . $exception->getMessage());
            return;
        }

        if (@file_put_contents($this->path, $line . PHP_EOL, FILE_APPEND | LOCK_EX) === false) {
            error_log('Hashcash request-header logging failed: unable to append to the configured file.');
        }
    }

    private function sanitize(string $value): string
    {
        $sanitized = preg_replace('/[\x00-\x1F\x7F]/', ' ', $value);
        $sanitized = is_string($sanitized) ? trim($sanitized) : '';

        return substr($sanitized, 0, self::MAXIMUM_VALUE_LENGTH);
    }
}
