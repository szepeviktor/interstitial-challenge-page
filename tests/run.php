<?php

declare(strict_types=1);

use SzepeViktor\WordPress\Waf\Challenge\ChallengeService;
use SzepeViktor\WordPress\Waf\Config;
use SzepeViktor\WordPress\Waf\Replay\NullReplayStore;
use SzepeViktor\WordPress\Waf\Replay\RedisReplayStore;
use SzepeViktor\WordPress\Waf\Replay\ReplayStore;
use SzepeViktor\WordPress\Waf\Request;
use SzepeViktor\WordPress\Waf\Scoring\DefaultScorer;
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
    challengeTtl: 300,
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

$clearance = $tokens->issueClearance($request->host, $now + 900);
assertSameValue(true, $tokens->validateClearance($clearance, $request->host, $now, 900), 'clearance');
assertSameValue(false, $tokens->validateClearance($clearance . 'x', $request->host, $now, 900), 'tampered clearance');

$wordpressCookie = 'wordpress-session-cookie';
$assertion = $tokens->issueAuthAssertion($request->host, $wordpressCookie, $now + 600);
assertSameValue(
    true,
    $tokens->validateAuthAssertion($assertion, $request->host, [$wordpressCookie], $now, 600),
    'auth assertion',
);

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
