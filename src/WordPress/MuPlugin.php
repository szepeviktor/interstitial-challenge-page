<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\WordPress;

use SzepeViktor\WordPress\Waf\Config;
use SzepeViktor\WordPress\Waf\Request;
use SzepeViktor\WordPress\Waf\Security\TokenService;

final class MuPlugin
{
    private const LOGIN_ERROR_COOKIE = 'hc_login_error';

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
        add_action('wp_login_failed', [$this, 'handleFailedLogin'], 10, 2);
        add_filter('wp_login_errors', [$this, 'restoreFailedLoginError']);
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

        $this->setCookie(
            $this->config->authCookie,
            $value,
            $expires,
            $request->scheme === 'https',
        );
    }

    public function clearAuthAssertion(): void
    {
        if (headers_sent()) {
            return;
        }

        $request = Request::fromGlobals($_SERVER, $_COOKIE, $_POST);
        $this->setCookie(
            $this->config->authCookie,
            '',
            time() - 3600,
            $request->scheme === 'https',
        );
    }

    public function handleFailedLogin(string $username, \WP_Error $error): void
    {
        if (headers_sent()) {
            return;
        }

        $request = Request::fromGlobals($_SERVER, $_COOKIE, $_POST);
        if (
            $request->method !== 'POST'
            || $request->path !== '/wp-login.php'
            || !isset($request->cookies[$this->config->clearanceCookie])
        ) {
            return;
        }

        $this->setCookie(
            $this->config->clearanceCookie,
            '',
            time() - 3600,
            $request->scheme === 'https',
        );

        $messages = [];
        foreach ($error->get_error_codes() as $code) {
            $messages[$code] = $error->get_error_messages($code);
        }

        $expires = time() + $this->config->challengeTtl;
        $loginError = $this->tokenService->issueLoginError(
            $request->host,
            $messages,
            $expires,
        );
        if ($loginError === null) {
            return;
        }

        $this->setCookie(
            self::LOGIN_ERROR_COOKIE,
            $loginError,
            $expires,
            $request->scheme === 'https',
            '/wp-login.php',
        );

        $redirectTo = isset($request->post['redirect_to'])
            && is_string($request->post['redirect_to'])
            ? $request->post['redirect_to']
            : '';

        if (wp_safe_redirect(wp_login_url($redirectTo), 303, 'Hashcash Interstitial')) {
            exit;
        }
    }

    public function restoreFailedLoginError(\WP_Error $errors): \WP_Error
    {
        $request = Request::fromGlobals($_SERVER, $_COOKIE, $_POST);
        $token = $request->cookies[self::LOGIN_ERROR_COOKIE] ?? '';
        if ($token === '') {
            return $errors;
        }

        $this->setCookie(
            self::LOGIN_ERROR_COOKIE,
            '',
            time() - 3600,
            $request->scheme === 'https',
            '/wp-login.php',
        );

        $messages = $this->tokenService->validateLoginError(
            $token,
            $request->host,
            time(),
            $this->config->challengeTtl,
        );
        if ($messages === null) {
            return $errors;
        }

        foreach ($messages as $code => $codeMessages) {
            foreach ($codeMessages as $message) {
                $errors->add($code, $message);
            }
        }

        return $errors;
    }

    private function setCookie(
        string $name,
        string $value,
        int $expires,
        bool $secure,
        string $path = '/',
    ): void
    {
        setcookie($name, $value, [
            'expires' => $expires,
            'path' => $path,
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }
}
