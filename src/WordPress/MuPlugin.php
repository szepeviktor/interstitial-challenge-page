<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\WordPress;

use SzepeViktor\WordPress\Waf\Config;
use SzepeViktor\WordPress\Waf\Request;
use SzepeViktor\WordPress\Waf\Security\TokenService;

final class MuPlugin
{
    private readonly TokenService $tokenService;

    public function __construct(private readonly Config $config)
    {
        $this->tokenService = new TokenService($this->config->secret);
    }

    public function register(): void
    {
        add_action('init', [$this, 'refreshAuthAssertion'], 0);
        add_action('set_logged_in_cookie', [$this, 'issueAuthAssertion'], 10, 1);
        add_action('clear_auth_cookie', [$this, 'clearAuthAssertion']);
        add_action('wp_logout', [$this, 'clearAuthAssertion']);
    }

    public function refreshAuthAssertion(): void
    {
        if (
            headers_sent()
            || !is_user_logged_in()
            || !defined('LOGGED_IN_COOKIE')
            || !isset($_COOKIE[LOGGED_IN_COOKIE])
            || !is_string($_COOKIE[LOGGED_IN_COOKIE])
        ) {
            return;
        }

        $this->issueAuthAssertion($_COOKIE[LOGGED_IN_COOKIE]);
    }

    public function issueAuthAssertion(string $wordpressCookie): void
    {
        if (headers_sent()) {
            return;
        }

        $request = Request::fromGlobals($_SERVER, $_COOKIE, $_POST);
        $expires = time() + $this->config->authAssertionTtl;
        $value = $this->tokenService->issueAuthAssertion(
            $request->host,
            $wordpressCookie,
            $expires,
        );

        $this->setCookie($value, $expires, $request->scheme === 'https');
    }

    public function clearAuthAssertion(): void
    {
        if (headers_sent()) {
            return;
        }

        $this->setCookie('', time() - 3600, is_ssl());
    }

    private function setCookie(string $value, int $expires, bool $secure): void
    {
        setcookie($this->config->authCookie, $value, [
            'expires' => $expires,
            'path' => '/',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }
}
