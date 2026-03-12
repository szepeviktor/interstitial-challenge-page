<?php
/**
 * Plugin Name: Hashcash Interstitial Challenge
 * Description: Minimal interstitial challenge page using original Hashcash stamps.
 * Version: 0.2.0
 * Author: Bitpenge
 */

declare(strict_types=1);

namespace HashcashInterstitial;

if (!defined('ABSPATH')) {
    exit;
}

final class Plugin
{
    private const BITS = 20;
    private const TTL = 300;
    private const OK_TTL = 900;
    private const COOKIE_OK = 'hc_ok';
    private const SCRIPT_HANDLE = 'hashcash-interstitial';

    public static function init(): void
    {
        add_action('template_redirect', [self::class, 'maybe_intercept'], 0);
    }

    public static function maybe_intercept(): void
    {
        if (is_admin() || wp_doing_ajax() || wp_doing_cron()) {
            return;
        }

        if (self::has_ok_cookie()) {
            return;
        }

        if (self::is_solved()) {
            self::set_ok_cookie();
            return;
        }

        self::render_challenge();
        exit;
    }

    private static function has_ok_cookie(): bool
    {
        return isset($_COOKIE[self::COOKIE_OK]) && $_COOKIE[self::COOKIE_OK] === '1';
    }

    private static function set_ok_cookie(): void
    {
        setcookie(self::COOKIE_OK, '1', time() + self::OK_TTL, COOKIEPATH ?: '/', COOKIE_DOMAIN, is_ssl(), true);
    }

    private static function is_solved(): bool
    {
        if (empty($_POST['hc_stamp'])) {
            return false;
        }

        $stamp = trim((string) $_POST['hc_stamp']);
        $parts = explode(':', $stamp);
        if (count($parts) !== 7 || $parts[0] !== '1') {
            return false;
        }

        $bits = (int) $parts[1];
        if ($bits !== self::BITS) {
            return false;
        }

        $date = self::parse_date($parts[2]);
        if ($date === null || abs(time() - $date) > self::TTL) {
            return false;
        }

        if ($parts[3] !== self::resource()) {
            return false;
        }

        if ($parts[5] === '' || $parts[6] === '') {
            return false;
        }

        $hash = sha1($stamp);
        return self::leading_zero_bits($hash) >= self::BITS;
    }

    private static function parse_date(string $date): ?int
    {
        $len = strlen($date);
        if ($len !== 6 && $len !== 12) {
            return null;
        }

        $format = $len === 6 ? 'ymd' : 'ymdHis';
        $dt = \DateTime::createFromFormat($format, $date, new \DateTimeZone('UTC'));
        if (!$dt) {
            return null;
        }

        return $dt->getTimestamp();
    }

    private static function leading_zero_bits(string $hex): int
    {
        $bits = 0;
        $len = strlen($hex);
        for ($i = 0; $i < $len; $i++) {
            $c = $hex[$i];
            if ($c === '0') {
                $bits += 4;
                continue;
            }

            $n = hexdec($c);
            if ($n >= 8) {
                return $bits;
            }
            if ($n >= 4) {
                return $bits + 1;
            }
            if ($n >= 2) {
                return $bits + 2;
            }
            if ($n >= 1) {
                return $bits + 3;
            }

            return $bits + 4;
        }

        return $bits;
    }

    private static function resource(): string
    {
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $scheme = is_ssl() ? 'https' : 'http';
        return $scheme . '://' . $host . $uri;
    }

    private static function enqueue_script(): void
    {
        $src = plugins_url('hashcash-interstitial.js', __FILE__);
        wp_enqueue_script(self::SCRIPT_HANDLE, $src, [], '0.2.0', true);
        $inline = 'window.HC=' . wp_json_encode([
            'bits' => self::BITS,
            'ttl' => self::TTL,
            'resource' => self::resource(),
            'action' => esc_url_raw($_SERVER['REQUEST_URI'] ?? '/'),
        ], JSON_UNESCAPED_SLASHES) . ';';
        wp_add_inline_script(self::SCRIPT_HANDLE, $inline, 'before');
    }

    private static function render_challenge(): void
    {
        if (!is_ssl()) {
            header('Content-Type: text/html; charset=utf-8');
            status_header(403);
            echo '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">';
            echo '<title>HTTPS Required</title>';
            echo '<style>body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;padding:40px;background:#f7f7f7;color:#111}';
            echo '.card{max-width:560px;margin:10vh auto;background:#fff;border:1px solid #ddd;border-radius:8px;padding:24px;box-shadow:0 4px 24px rgba(0,0,0,.08)}';
            echo '</style></head><body><div class="card"><h1>HTTPS Required</h1><p>This challenge requires HTTPS for WebCrypto.</p></div></body></html>';
            return;
        }

        self::enqueue_script();
        header('Content-Type: text/html; charset=utf-8');
        status_header(429);

        echo '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">';
        echo '<title>Hold on</title>';
        echo '<style>body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;padding:40px;background:#f7f7f7;color:#111}';
        echo '.card{max-width:560px;margin:10vh auto;background:#fff;border:1px solid #ddd;border-radius:8px;padding:24px;box-shadow:0 4px 24px rgba(0,0,0,.08)}';
        echo 'button{background:#111;color:#fff;border:0;border-radius:6px;padding:10px 14px;font-size:14px;cursor:pointer}';
        echo 'code{background:#f0f0f0;padding:2px 6px;border-radius:4px}</style></head><body>';
        echo '<div class="card"><h1>One more step</h1><p>We need a quick Hashcash proof-of-work.</p>';
        echo '<p>Bits: <code>' . esc_html((string) self::BITS) . '</code></p>';
        echo '<form id="hc" method="post" action="' . esc_attr(esc_url_raw($_SERVER['REQUEST_URI'] ?? '/')) . '">';
        echo '<input type="hidden" name="hc_stamp" id="hc_stamp" value="">';
        echo '<button type="button" id="hc_btn">Compute &amp; Continue</button>';
        echo '<noscript><p>JavaScript required.</p></noscript></form>';
        wp_print_scripts([self::SCRIPT_HANDLE]);
        echo '</div></body></html>';
    }
}

Plugin::init();
