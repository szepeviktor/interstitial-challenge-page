<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf;

final class Request
{
    /**
     * @param array<string, string> $headers
     * @param array<string, string> $cookies
     * @param array<string, mixed> $post
     */
    public function __construct(
        public readonly string $method,
        public readonly string $scheme,
        public readonly string $host,
        public readonly string $target,
        public readonly string $path,
        public readonly array $headers,
        public readonly array $cookies,
        public readonly array $post,
        public readonly string $protocol = '',
        public readonly string $clientIp = '',
    ) {
    }

    /**
     * @param array<string, mixed> $server
     * @param array<string, mixed> $cookies
     * @param array<string, mixed> $post
     */
    public static function fromGlobals(array $server, array $cookies, array $post): self
    {
        $target = self::normalizeTarget((string) ($server['REQUEST_URI'] ?? '/'));
        $path = parse_url($target, PHP_URL_PATH);

        return new self(
            method: strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET')),
            scheme: self::detectScheme($server),
            host: self::normalizeHost((string) ($server['HTTP_HOST'] ?? 'localhost')),
            target: $target,
            path: is_string($path) && $path !== '' ? $path : '/',
            headers: self::extractHeaders($server),
            cookies: self::stringValues($cookies),
            post: $post,
            protocol: strtoupper((string) ($server['SERVER_PROTOCOL'] ?? '')),
            clientIp: (string) ($server['REMOTE_ADDR'] ?? ''),
        );
    }

    public function header(string $name): string
    {
        return $this->headers[strtolower($name)] ?? '';
    }

    public function isHtmlDocumentNavigation(): bool
    {
        if ($this->method !== 'GET' || stripos($this->header('accept'), 'text/html') === false) {
            return false;
        }

        $destination = strtolower($this->header('sec-fetch-dest'));
        return $destination === '' || $destination === 'document';
    }

    public function encodedResource(): string
    {
        return rawurlencode($this->scheme . '://' . $this->host . $this->target);
    }

    /**
     * @param array<string, mixed> $server
     *
     * @return array<string, string>
     */
    private static function extractHeaders(array $server): array
    {
        $headers = [];

        foreach ($server as $name => $value) {
            if (!is_string($value)) {
                continue;
            }

            if (str_starts_with($name, 'HTTP_')) {
                $header = strtolower(str_replace('_', '-', substr($name, 5)));
                $headers[$header] = $value;
            }
        }

        if (isset($server['CONTENT_TYPE']) && is_string($server['CONTENT_TYPE'])) {
            $headers['content-type'] = $server['CONTENT_TYPE'];
        }

        return $headers;
    }

    /**
     * @param array<string, mixed> $server
     */
    private static function detectScheme(array $server): string
    {
        $forwarded = strtolower((string) ($server['HTTP_X_FORWARDED_PROTO'] ?? ''));
        if (str_starts_with($forwarded, 'https')) {
            return 'https';
        }

        $cfVisitor = json_decode((string) ($server['HTTP_CF_VISITOR'] ?? ''), true);
        if (is_array($cfVisitor) && ($cfVisitor['scheme'] ?? null) === 'https') {
            return 'https';
        }

        $https = strtolower((string) ($server['HTTPS'] ?? ''));
        return ($https !== '' && $https !== 'off') || (int) ($server['SERVER_PORT'] ?? 0) === 443
            ? 'https'
            : 'http';
    }

    private static function normalizeHost(string $host): string
    {
        $normalized = preg_replace('/[^a-z0-9.\-:\[\]]/i', '', strtolower($host));
        return is_string($normalized) && $normalized !== '' ? $normalized : 'localhost';
    }

    private static function normalizeTarget(string $target): string
    {
        $target = str_replace(["\r", "\n"], '', $target);
        return '/' . ltrim($target, '/');
    }

    /**
     * @param array<string, mixed> $values
     *
     * @return array<string, string>
     */
    private static function stringValues(array $values): array
    {
        $strings = [];

        foreach ($values as $name => $value) {
            if (is_string($value)) {
                $strings[$name] = $value;
            }
        }

        return $strings;
    }
}
