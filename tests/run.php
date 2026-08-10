<?php

declare(strict_types=1);

use SzepeViktor\WordPress\Waf\Challenge\ChallengeService;
use SzepeViktor\WordPress\Waf\Config;
use SzepeViktor\WordPress\Waf\Replay\NullReplayStore;
use SzepeViktor\WordPress\Waf\Replay\RedisReplayStore;
use SzepeViktor\WordPress\Waf\Replay\ReplayStore;
use SzepeViktor\WordPress\Waf\Request;
use SzepeViktor\WordPress\Waf\RequestDecision;
use SzepeViktor\WordPress\Waf\RequestPolicy;
use SzepeViktor\WordPress\Waf\Scoring\DefaultScorer;
use SzepeViktor\WordPress\Waf\Scoring\Rules\EmergencyRule;
use SzepeViktor\WordPress\Waf\Scoring\Rules\AlphabeticalBrowserHeadersRule;
use SzepeViktor\WordPress\Waf\Scoring\Rules\ChromeHttp11ConnectionRule;
use SzepeViktor\WordPress\Waf\Scoring\Rules\FetchMetadataRule;
use SzepeViktor\WordPress\Waf\Security\TokenService;

require dirname(__DIR__) . '/vendor/autoload.php';

function assertSameValue(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        throw new RuntimeException(
            $message . ': expected ' . var_export($expected, true)
            . ', got ' . var_export($actual, true),
        );
    }
}

$now = time();
$config = new Config(
    secret: str_repeat('s', 32),
    bits: 8,
    challengeTtl: 30,
);
$request = Request::fromGlobals(
    [
        'REQUEST_METHOD' => 'GET',
        'REQUEST_URI' => '/protected?next=https://example.net/',
        'HTTP_HOST' => 'example.com',
        'HTTPS' => 'on',
        'HTTP_ACCEPT' => 'text/html',
        'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.9',
        'HTTP_USER_AGENT' => 'Mozilla/5.0 Firefox/140.0',
        'HTTP_SEC_FETCH_DEST' => 'document',
        'HTTP_SEC_FETCH_MODE' => 'navigate',
        'HTTP_SEC_FETCH_SITE' => 'none',
        'HTTP_SEC_FETCH_USER' => '?1',
    ],
    [],
    [],
);
$tokens = new TokenService($config->secret);
$defaultScorer = new DefaultScorer();
$requestPolicy = new RequestPolicy($config->requiredClearancePaths);

$languageRequest = static function (string $acceptLanguage) use ($request): Request {
    return new Request(
        method: $request->method,
        scheme: $request->scheme,
        host: $request->host,
        target: $request->target,
        path: $request->path,
        headers: array_merge($request->headers, ['accept-language' => $acceptLanguage]),
        cookies: $request->cookies,
        post: $request->post,
    );
};

assertSameValue(0, $defaultScorer->score($languageRequest('en'))->value, 'bare language score');
assertSameValue(0, $defaultScorer->score($languageRequest('en-US, zh-CN;q=0.8'))->value, 'Chinese language score');
assertSameValue(0, $defaultScorer->score($languageRequest('ZH-tw'))->value, 'case-insensitive Chinese language score');
assertSameValue(0, $defaultScorer->score($languageRequest('en-US'))->value, 'ordinary language score');
assertSameValue(10, $defaultScorer->score($languageRequest(''))->value, 'missing language score');

$withHeaders = static function (array $headers) use ($request): Request {
    return new Request(
        method: $request->method,
        scheme: $request->scheme,
        host: $request->host,
        target: $request->target,
        path: $request->path,
        headers: array_merge($request->headers, $headers),
        cookies: $request->cookies,
        post: $request->post,
    );
};

assertSameValue(
    60,
    $defaultScorer->score($withHeaders(['user-agent' => 'curl/8.14.1']))->value,
    'scripted client score',
);
assertSameValue(
    60,
    $defaultScorer->score($withHeaders(['user-agent' => '']))->value,
    'missing user agent score',
);
assertSameValue(
    50,
    $defaultScorer->score($withHeaders(['sec-fetch-mode' => 'cors']))->value,
    'inconsistent Fetch Metadata score',
);
assertSameValue(
    10,
    $defaultScorer->score($withHeaders([
        'accept-language' => '',
        'sec-fetch-dest' => '',
        'sec-fetch-mode' => '',
        'sec-fetch-site' => '',
        'sec-fetch-user' => '',
    ]))->value,
    'privacy-conscious browser score',
);
assertSameValue(
    15,
    $defaultScorer->score($withHeaders([
        'sec-fetch-mode' => '',
        'sec-fetch-site' => '',
    ]))->value,
    'incomplete Fetch Metadata score',
);

$suspiciousHeaders = [
    'accept' => 'text/html,application/xhtml+xml',
    'accept-encoding' => 'gzip, deflate, br, zstd',
    'accept-language' => 'en-US,en;q=0.9',
    'cache-control' => 'max-age=0',
    'host' => 'example.com',
    'referer' => 'https://example.com/',
    'sec-ch-ua' => '"Chromium";v="144", "Google Chrome";v="144"',
    'sec-ch-ua-mobile' => '?0',
    'sec-ch-ua-platform' => '"macOS"',
    'sec-fetch-dest' => 'document',
    'sec-fetch-mode' => 'navigate',
    'sec-fetch-site' => 'none',
    'sec-fetch-user' => '?1',
    'upgrade-insecure-requests' => '1',
    'user-agent' => 'Mozilla/5.0 Chrome/144.0.0.0 Safari/537.36',
];
$suspiciousRequest = new Request(
    method: 'GET',
    scheme: 'https',
    host: 'example.com',
    target: '/',
    path: '/',
    headers: $suspiciousHeaders,
    cookies: [],
    post: [],
    protocol: 'HTTP/1.1',
);

assertSameValue(
    30,
    (new AlphabeticalBrowserHeadersRule())->evaluate($suspiciousRequest)->value,
    'alphabetical browser headers score',
);
assertSameValue(
    50,
    (new FetchMetadataRule())->evaluate($suspiciousRequest)->value,
    'referer contradicts Sec-Fetch-Site none',
);
assertSameValue(
    20,
    (new ChromeHttp11ConnectionRule())->evaluate($suspiciousRequest)->value,
    'direct Chrome HTTP/1.1 connection score',
);
assertSameValue(
    100,
    $defaultScorer->score($suspiciousRequest)->value,
    'combined forged Chrome score',
);

$proxiedSuspiciousRequest = new Request(
    method: $suspiciousRequest->method,
    scheme: $suspiciousRequest->scheme,
    host: $suspiciousRequest->host,
    target: $suspiciousRequest->target,
    path: $suspiciousRequest->path,
    headers: array_merge($suspiciousRequest->headers, ['via' => '1.1 proxy.example']),
    cookies: $suspiciousRequest->cookies,
    post: $suspiciousRequest->post,
    protocol: $suspiciousRequest->protocol,
);
assertSameValue(
    0,
    (new ChromeHttp11ConnectionRule())->evaluate($proxiedSuspiciousRequest)->value,
    'proxy may remove the HTTP/1.1 Connection header',
);

$realisticChromeHeaders = [
    'host' => 'example.com',
    'connection' => 'keep-alive',
    'sec-ch-ua' => '"Chromium";v="150", "Google Chrome";v="150"',
    'sec-ch-ua-mobile' => '?0',
    'sec-ch-ua-platform' => '"Windows"',
    'upgrade-insecure-requests' => '1',
    'user-agent' => 'Mozilla/5.0 Chrome/150.0.0.0 Safari/537.36',
    'accept' => 'text/html,application/xhtml+xml',
    'sec-fetch-site' => 'none',
    'sec-fetch-mode' => 'navigate',
    'sec-fetch-user' => '?1',
    'sec-fetch-dest' => 'document',
    'accept-encoding' => 'gzip, deflate, br, zstd',
    'accept-language' => 'en-US,en;q=0.9',
];
$realisticChromeRequest = new Request(
    method: 'GET',
    scheme: 'https',
    host: 'example.com',
    target: '/',
    path: '/',
    headers: $realisticChromeHeaders,
    cookies: [],
    post: [],
    protocol: 'HTTP/1.1',
);
assertSameValue(
    0,
    (new AlphabeticalBrowserHeadersRule())->evaluate($realisticChromeRequest)->value,
    'realistic Chrome header order',
);
assertSameValue(
    0,
    (new ChromeHttp11ConnectionRule())->evaluate($realisticChromeRequest)->value,
    'realistic Chrome HTTP/1.1 connection',
);

$sensitivePathRequest = new Request(
    method: $request->method,
    scheme: $request->scheme,
    host: $request->host,
    target: '/.env',
    path: '/.env',
    headers: $request->headers,
    cookies: $request->cookies,
    post: $request->post,
);
assertSameValue(80, $defaultScorer->score($sensitivePathRequest)->value, 'sensitive path score');

$traversalRequest = new Request(
    method: $request->method,
    scheme: $request->scheme,
    host: $request->host,
    target: '/wp-content/%2e%2e/wp-config.php',
    path: '/wp-content/%2e%2e/wp-config.php',
    headers: $request->headers,
    cookies: $request->cookies,
    post: $request->post,
);
assertSameValue(80, $defaultScorer->score($traversalRequest)->value, 'path traversal score');

$doubleEncodedTraversalRequest = new Request(
    method: $request->method,
    scheme: $request->scheme,
    host: $request->host,
    target: '/wp-content/%252e%252e/wp-config.php',
    path: '/wp-content/%252e%252e/wp-config.php',
    headers: $request->headers,
    cookies: $request->cookies,
    post: $request->post,
);
assertSameValue(
    80,
    $defaultScorer->score($doubleEncodedTraversalRequest)->value,
    'double-encoded path traversal score',
);

$emergencyRequest = new Request(
    method: 'POST',
    scheme: 'https',
    host: 'example.com',
    target: '/wp-json/wp/v2/users?context=edit',
    path: '/wp-json/wp/v2/users',
    headers: [
        'accept' => 'text/html',
        'accept-language' => 'en-US,en;q=0.9',
        'host' => 'example.com',
        'user-agent' => 'Mozilla/5.0',
        'x-attack' => 'ProbeRunner',
    ],
    cookies: [],
    post: [],
    protocol: 'HTTP/1.1',
    clientIp: '203.0.113.42',
);
$emergencyRule = new EmergencyRule([
    ['type' => 'path_exact', 'value' => '/wp-json/wp/v2/users', 'score' => 10, 'reason' => 'emergency_path_exact'],
    ['type' => 'path_prefix', 'value' => '/wp-json/', 'score' => 10, 'reason' => 'emergency_path_prefix'],
    ['type' => 'path_contains', 'value' => '/v2/', 'score' => 10, 'reason' => 'emergency_path_contains'],
    ['type' => 'path_regex', 'value' => '~^/wp-json/.*/users$~', 'score' => 10, 'reason' => 'emergency_path_regex'],
    ['type' => 'method', 'value' => 'POST', 'score' => 10, 'reason' => 'emergency_method'],
    ['type' => 'method_path', 'value' => 'POST /wp-json/wp/v2/users', 'score' => 10, 'reason' => 'emergency_method_path'],
    ['type' => 'header_missing', 'name' => 'x-missing', 'score' => 10, 'reason' => 'emergency_header_missing'],
    ['type' => 'header_equals', 'name' => 'x-attack', 'value' => 'ProbeRunner', 'score' => 10, 'reason' => 'emergency_header_equals'],
    ['type' => 'header_contains', 'name' => 'x-attack', 'value' => 'runner', 'score' => 10, 'reason' => 'emergency_header_contains'],
    ['type' => 'header_regex', 'name' => 'x-attack', 'value' => '~ProbeRunn(er)$~', 'score' => 10, 'reason' => 'emergency_header_regex'],
    ['type' => 'header_names_equals', 'value' => 'accept,accept-language,host,user-agent,x-attack', 'score' => 10, 'reason' => 'emergency_header_names_equals'],
    ['type' => 'ip_exact', 'value' => '203.0.113.42', 'score' => 10, 'reason' => 'emergency_ip_exact'],
    ['type' => 'ip_cidr', 'value' => '203.0.113.0/24', 'score' => 10, 'reason' => 'emergency_ip_cidr'],
]);
assertSameValue(100, $emergencyRule->evaluate($emergencyRequest)->value, 'emergency rule score is capped');
assertSameValue(
    60,
    (new DefaultScorer(new Config(
        secret: str_repeat('s', 32),
        emergencyRules: [
            ['type' => 'path_prefix', 'value' => '/wp-json/', 'score' => 60, 'reason' => 'emergency_wp_json'],
        ],
    )))->score($emergencyRequest)->value,
    'default scorer includes configured emergency rules',
);
assertSameValue(
    0,
    (new EmergencyRule([
        ['type' => 'ip_cidr', 'value' => '2001:db8::/32', 'score' => 100, 'reason' => 'emergency_ipv6_cidr'],
    ]))->evaluate($emergencyRequest)->value,
    'IPv4 request does not match IPv6 emergency CIDR',
);

try {
    new Config(
        secret: str_repeat('s', 32),
        emergencyRules: [
            ['type' => 'path_regex', 'value' => '(', 'score' => 100],
        ],
    );
    throw new RuntimeException('Invalid emergency regex was accepted.');
} catch (InvalidArgumentException) {
}

$requestFor = static function (
    string $path,
    string $method = 'GET',
    array $headers = [],
) use ($request): Request {
    return new Request(
        method: $method,
        scheme: $request->scheme,
        host: $request->host,
        target: $path,
        path: parse_url($path, PHP_URL_PATH) ?: '/',
        headers: array_merge($request->headers, $headers),
        cookies: $request->cookies,
        post: $request->post,
    );
};

assertSameValue(
    RequestDecision::RequireClearance,
    $requestPolicy->decide($requestFor('/checkout')),
    'checkout requires clearance',
);
assertSameValue(
    RequestDecision::RequireClearance,
    $requestPolicy->decide($requestFor('/checkout/?coupon=welcome')),
    'checkout query requires clearance',
);
assertSameValue(
    RequestDecision::RequireClearance,
    $requestPolicy->decide($requestFor('/wp-login.php?action=lostpassword')),
    'WordPress login navigation requires clearance',
);
assertSameValue(
    RequestDecision::RequireClearance,
    $requestPolicy->decide($requestFor('/wp-login.php?wc-ajax=checkout')),
    'WooCommerce AJAX query cannot bypass WordPress login clearance',
);
assertSameValue(
    RequestDecision::RequireClearance,
    $requestPolicy->decide($requestFor(
        '/wp-login.php',
        'POST',
        ['content-type' => 'application/x-www-form-urlencoded'],
    )),
    'WordPress login submission requires clearance',
);
assertSameValue(
    RequestDecision::Normal,
    $requestPolicy->decide($requestFor('/checkout-later')),
    'required paths use exact matching',
);
assertSameValue(
    RequestDecision::Normal,
    $requestPolicy->decide($requestFor('/checkout?wc-ajax=checkout')),
    'WooCommerce AJAX bypasses mandatory clearance policy',
);
assertSameValue(
    RequestDecision::Bypass,
    $requestPolicy->decide($requestFor(
        '/wp-json/wc/store/v1/checkout',
        'POST',
        ['accept' => 'application/json'],
    )),
    'WooCommerce Store API bypasses the page policy',
);

$clearance = $tokens->issueClearance($request->host, $now + 900);
assertSameValue(true, $tokens->validateClearance($clearance, $request->host, $now, 900), 'clearance');
assertSameValue(false, $tokens->validateClearance($clearance . 'x', $request->host, $now, 900), 'tampered clearance');

$makeStamp = static function (ChallengeService $service) use ($request, $now): string {
    $challenge = $service->create($request, $now);
    $date = gmdate('ymdHis', $now);

    for ($counter = 0; ; $counter++) {
        $stamp = implode(':', [
            '1',
            (string) $challenge->bits,
            $date,
            $challenge->resource,
            $challenge->token,
            'random',
            base64_encode((string) $counter),
        ]);

        if (str_starts_with(sha1($stamp), '00')) {
            return $stamp;
        }
    }
};

$stateless = new ChallengeService($config, $tokens, new NullReplayStore());
$statelessStamp = $makeStamp($stateless);
assertSameValue(true, $stateless->verify($request, $statelessStamp, $now), 'stateless first use');
assertSameValue(true, $stateless->verify($request, $statelessStamp, $now), 'stateless replay');

$singleUseStore = new class implements ReplayStore {
    /** @var array<string, true> */
    private array $claims = [];

    public function claim(string $nonce, int $expires, int $now): bool
    {
        if (isset($this->claims[$nonce])) {
            return false;
        }

        $this->claims[$nonce] = true;
        return true;
    }
};
$singleUse = new ChallengeService($config, $tokens, $singleUseStore);
$singleUseStamp = $makeStamp($singleUse);
assertSameValue(true, $singleUse->verify($request, $singleUseStamp, $now), 'stored first use');
assertSameValue(false, $singleUse->verify($request, $singleUseStamp, $now), 'stored replay');

if (class_exists(Redis::class)) {
    $redis = new class extends Redis {
        /** @var array<string, string> */
        private array $values = [];

        public function set(string $key, mixed $value, mixed $options = null): bool
        {
            if (isset($this->values[$key])) {
                return false;
            }

            $this->values[$key] = (string) $value;
            return true;
        }
    };
    $redisStore = new RedisReplayStore($redis, 'test:');
    assertSameValue(true, $redisStore->claim('nonce', $now + 60, $now), 'Redis first claim');
    assertSameValue(false, $redisStore->claim('nonce', $now + 60, $now), 'Redis replay');
}

echo "All tests passed.\n";
