# WordPress Hashcash WAF

A Composer package that scores and challenges requests before WordPress boots.

All PHP classes use the `SzepeViktor\WordPress\Waf` namespace.

## Responsibilities

Code invoked from `wp-config.php`:

- builds a framework-independent request;
- excludes background and non-document requests;
- requires a valid challenge clearance on configured sensitive pages;
- runs the injected scoring system;
- validates clearance cookies;
- creates and signs stateless Hashcash challenges;
- renders the interstitial page;
- receives and verifies challenge POST requests;
- optionally claims completed proofs in Redis;
- issues signed clearance cookies.

## Installation

Install the package through the Composer autoloader loaded by `wp-config.php`.
Define a dedicated WAF secret and invoke the early gate before `wp-settings.php`
is required:

```php
use SzepeViktor\WordPress\Waf\Config;
use SzepeViktor\WordPress\Waf\EarlyGate;
use SzepeViktor\WordPress\Waf\Replay\NullReplayStore;

require_once __DIR__ . '/vendor/autoload.php';

define('HASHCASH_INTERSTITIAL_SECRET', 'at-least-32-random-bytes');

(new EarlyGate(
    config: Config::fromConstants(),
    replayStore: new NullReplayStore(),
))->run();
```

`HASHCASH_INTERSTITIAL_SECRET` is required and must contain at least 32 bytes.
WordPress authentication salts are never used as WAF signing keys. The same
dedicated secret signs challenges and clearance cookies.

The WAF cookie is host-only. The package does not read WordPress's
`COOKIE_DOMAIN` constant.

## Scoring

The default scorer applies these rules:

- missing `User-Agent`: +60;
- a `User-Agent` identifying common scripted HTTP clients: +60;
- an oversized `User-Agent`: +30;
- missing `Accept-Language`: +10;
- oversized `Accept-Language`: +20;
- inconsistent Fetch Metadata headers: +50;
- a non-empty `Referer` combined with `Sec-Fetch-Site: none`: +50;
- incomplete Fetch Metadata when at least one such header is present: +15;
- at least 10 browser navigation headers emitted in alphabetical order: +30;
- an unexpected `Connection` value on a direct Chrome HTTP/1.1 navigation:
  +20;
- path traversal or common sensitive-file probes: +80.

Missing Fetch Metadata does not score by itself, because older and
privacy-focused browsers may omit it. The default rules do not challenge based
on language, country, or a generic bot/crawler substring. Verified search
engine handling should be implemented separately from user-agent scoring.
The Chrome HTTP/1.1 connection rule is skipped when a recognized forwarding
header is present, because proxies may legitimately remove hop-by-hop headers.

For custom scoring, implement `Scorer` and return a score between 0 and 100:

```php
use SzepeViktor\WordPress\Waf\Request;
use SzepeViktor\WordPress\Waf\Scoring\Score;
use SzepeViktor\WordPress\Waf\Scoring\Scorer;

final class SiteScorer implements Scorer
{
    public function score(Request $request): Score
    {
        $score = 0;
        $reasons = [];

        if ($request->header('user-agent') === '') {
            $score += 50;
            $reasons[] = 'missing_user_agent';
        }

        return new Score(min($score, 100), $reasons);
    }
}
```

The default challenge threshold is 50.

## Replay modes

### Stateless

`NullReplayStore` performs no persistence. Challenges are signed and expire
after 30 seconds, but a valid proof can be replayed during that window.

### Redis

`RedisReplayStore` uses atomic Redis `SET NX EX`. The first completed proof
claims the nonce; subsequent submissions of the same proof fail.

```php
$redis = new Redis();
$redis->connect('127.0.0.1', 6379, 0.25);

$store = new RedisReplayStore($redis);
```

Redis must be connected before constructing the store. No Redis connection is
created by the package.

## Configuration constants

```php
define('HASHCASH_INTERSTITIAL_SECRET', 'at-least-32-random-bytes');
define('HASHCASH_INTERSTITIAL_THRESHOLD', 50);
define('HASHCASH_INTERSTITIAL_BITS', 20);
define('HASHCASH_INTERSTITIAL_CHALLENGE_TTL', 30);
define('HASHCASH_INTERSTITIAL_CLEARANCE_TTL', 900);
define('HASHCASH_INTERSTITIAL_FAIL_OPEN', true);
define('HASHCASH_INTERSTITIAL_LOG', '/var/log/hashcash-interstitial/example.com.log');
define('HASHCASH_INTERSTITIAL_REQUIRED_PATHS', ['/checkout', '/checkout/', '/wp-login.php']);
define('HASHCASH_INTERSTITIAL_EMERGENCY_RULES', [
    ['type' => 'path_prefix', 'value' => '/wp-json/', 'score' => 80, 'reason' => 'emergency_wp_json'],
]);
```

`HASHCASH_INTERSTITIAL_REQUIRED_PATHS` defaults to the paths shown above.
Matching is exact and ignores the query string, so `/checkout-later` is not
protected. Normal HTML navigations to these paths require a valid, host-bound
`hc_clearance` cookie regardless of request score or WordPress authentication.
Direct `POST` requests to `/wp-login.php` also require clearance. Challenge
proof submissions remain accepted, and WooCommerce `wc-ajax` requests are not
treated as checkout-page navigations.

`HASHCASH_INTERSTITIAL_LOG` is optional. When it is defined, eligible requests
scoring from 30 through 49 are appended to that file as newline-delimited JSON.
The directory and writable file must be created outside the web root by the
server administrator; the package does not create directories.

Each record contains the UTC timestamp, method, normalized host, target, score,
rule reasons, and an allowlist of useful request headers. Header values have
control characters removed and are limited to 2,048 bytes. `Cookie`,
`Authorization`, challenge stamps, authentication tokens, and unrecognized
headers are never logged. A log write failure is reported through PHP's error
log and does not block the request.

`HASHCASH_INTERSTITIAL_EMERGENCY_RULES` is optional. It accepts a list of
score-only rules that are appended to the default scorer, so matching requests
receive a challenge when their final score reaches
`HASHCASH_INTERSTITIAL_THRESHOLD`. Supported rule types:

- `path_exact`, `path_prefix`, `path_contains`, `path_regex`;
- `method`, with a value such as `POST`;
- `method_path`, with a value such as `POST /wp-login.php`;
- `header_missing`, `header_equals`, `header_contains`, `header_regex`;
- `header_names_equals`;
- `ip_exact`, `ip_cidr`.

Header rules require `name`; every rule except `header_missing` requires
`value`. `score` must be an integer from 0 through 100. `reason` is optional
and defaults to `emergency_` plus the rule type. If the constant contains an
invalid rule, the whole emergency rule list is ignored and the problem is
written to PHP's error log.

## Development

Run PHPStan at level 5:

```console
composer analyse
```

GitHub Actions runs the 10 supported combinations on Ubuntu 24.04:

- PHP 8.1 and 8.5 through the runtime selected by `setup-php`;
- Node.js major versions 22 and 26;
- the first WordPress releases in each tested line: 5.9, 6.0, and 7.0.

WordPress 5.9 with PHP 8.5 is excluded because WordPress 5.9 supports PHP
only through 8.1. Both Node.js versions still run against every supported
WordPress/PHP pair.

The workflow installs an isolated WordPress fixture under the runner's
temporary directory and starts MySQL and Redis directly on the host. It does
not use service containers or Docker.

### End-to-end tests

The E2E suite uses the existing WordPress installation at
`/home/viktor/chatgpt-is-super`, `/usr/bin/php`, Node's built-in test runner,
and `playwright-core` with the locally installed Google Chrome. It does not
use Docker, `wp-env`, `@playwright/test`, or a downloaded Playwright browser.

The WordPress database and Redis must be reachable, `/usr/bin/php` must be PHP
8.1 or newer with `ext-mysqli` and `ext-redis`, and the fixture must contain
the `admin` user. Install the single Node dependency and run the suite:

```console
npm install
npm run test:e2e
```

The suite starts and stops its own PHP server. A test router loads the package
before WordPress, maps an isolated MU-plugin directory, lowers Hashcash to
eight bits, fakes HTTPS through `X-Forwarded-Proto`, and uses the production
`RedisReplayStore` with a unique, automatically cleaned key prefix. It does
not modify the WordPress fixture files; the login/logout scenario creates and
destroys a normal WordPress session.

Environment overrides:

```console
HC_E2E_WORDPRESS_PATH=/home/viktor/chatgpt-is-super
HC_E2E_WP_USER=admin
HC_E2E_WP_PASSWORD=admin
HC_E2E_PORT=8090
HC_E2E_REDIS_HOST=127.0.0.1
HC_E2E_REDIS_PORT=6379
PLAYWRIGHT_CHROME_PATH=/usr/bin/google-chrome
```

Coverage includes scoring and bypass behavior, sensitive paths, Fetch
Metadata, HTTP-only rejection, challenge and cache headers, proof creation and
submission, exact resource/scheme/authority/query binding, malformed and
tampered stamps, hostile-target escaping and local redirect confinement,
clearance-cookie tampering, Redis TTL, sequential and concurrent replay
rejection, fail-open/fail-closed behavior, replay-store recovery without
exception leakage, and the browser WebCrypto flow.

The suite also performs a mutation sub-run with `NullReplayStore` deliberately
substituted for Redis. It requires both sequential and concurrent replay
contracts to fail under that substitution, proving that the tests detect an
accidental downgrade to stateless replay handling.

## Cloudflare caching

This package only sees requests that reach the origin. A Cloudflare full-page
cache hit bypasses `wp-config.php`. Enforce challenges at the Cloudflare edge
when every cached page view must be evaluated.
