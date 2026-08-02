<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf\Challenge;

final class ChallengeRenderer
{
    public function send(Challenge $challenge, string $action): never
    {
        $configuration = json_encode(
            [
                'bits' => $challenge->bits,
                'resource' => $challenge->resource,
                'token' => $challenge->token,
            ],
            JSON_THROW_ON_ERROR
                | JSON_UNESCAPED_SLASHES
                | JSON_HEX_TAG
                | JSON_HEX_AMP
                | JSON_HEX_APOS
                | JSON_HEX_QUOT,
        );
        $escapedAction = htmlspecialchars($action, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $this->headers(429);
        header('HC-Mitigated: challenge');

        echo <<<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Security check</title>
<style>
*{box-sizing:border-box}
html{background:#f0f0f1}
body{min-width:0;margin:0;background:#f0f0f1;color:#3c434a;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;font-size:13px;line-height:1.4}
.login{width:320px;max-width:calc(100% - 40px);margin:auto;padding:5% 0 0}
.logo{width:84px;height:84px;margin:0 auto 24px;background:url("/wp-admin/images/wordpress-logo-gray.svg") center/84px 84px no-repeat}
.card{width:320px;max-width:100%;padding:26px 24px;background:#fff;border:1px solid #c3c4c7;box-shadow:0 1px 3px rgba(0,0,0,.04)}
h1{margin:0 0 16px;color:#1d2327;font-size:20px;font-weight:400;line-height:1.3}
p{margin:0}
.status{font-size:14px;line-height:21px}
.detail{margin-top:16px;color:#50575e;line-height:1.5}
.spinner{display:inline-block;width:14px;height:14px;margin:0 7px -2px 0;border:2px solid #c3c4c7;border-top-color:#3858e9;border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.spinner{animation-duration:1.6s}}
@media (max-width:782px){.login{padding-top:20px}}
</style>
</head>
<body>
<main class="login">
<div class="logo" role="img" aria-label="WordPress"></div>
<section class="card">
<h1>Security check</h1>
<p id="hc_status" class="status" role="status" aria-live="polite"><span class="spinner" aria-hidden="true"></span>Verifying your browser&hellip;</p>
<p class="detail">This quick check helps protect the site from automated abuse.</p>
<form id="hc" method="post" action="{$escapedAction}">
<input type="hidden" name="hc_challenge" value="1">
<input type="hidden" name="hc_stamp" id="hc_stamp" value="">
<noscript><p>JavaScript is required to complete this security check.</p></noscript>
</form>
</section>
</main>
<script>
window.HC={$configuration};
(() => {
    const config = window.HC;
    const statusElement = document.getElementById('hc_status');
    const stampElement = document.getElementById('hc_stamp');
    const form = document.getElementById('hc');
    const encoder = new TextEncoder();
    const batchSize = 1024;
    const sha1 = async (value) => new Uint8Array(
        await crypto.subtle.digest('SHA-1', encoder.encode(value))
    );
    const leadingZeroBits = (digest) => {
        let bits = 0;
        for (const byte of digest) {
            if (byte === 0) { bits += 8; continue; }
            return bits + Math.clz32(byte) - 24;
        }
        return bits;
    };
    const randomValue = () => {
        const bytes = new Uint8Array(12);
        crypto.getRandomValues(bytes);
        return btoa(String.fromCharCode(...bytes)).replace(/=+$/g, '');
    };
    const dateStamp = () => {
        const date = new Date();
        return String(date.getUTCFullYear()).slice(-2)
            + String(date.getUTCMonth() + 1).padStart(2, '0')
            + String(date.getUTCDate()).padStart(2, '0')
            + String(date.getUTCHours()).padStart(2, '0')
            + String(date.getUTCMinutes()).padStart(2, '0')
            + String(date.getUTCSeconds()).padStart(2, '0');
    };
    const solve = async () => {
        const date = dateStamp();
        const random = randomValue();
        for (let counter = 0; ; counter += batchSize) {
            const stamps = Array.from({ length: batchSize }, (_, offset) => {
                const encodedCounter = btoa(String(counter + offset)).replace(/=+$/g, '');
                return `1:\${config.bits}:\${date}:\${config.resource}:\${config.token}:\${random}:\${encodedCounter}`;
            });
            const digests = await Promise.all(stamps.map(sha1));
            for (let offset = 0; offset < batchSize; offset += 1) {
                if (leadingZeroBits(digests[offset]) >= config.bits) {
                    stampElement.value = stamps[offset];
                    form.submit();
                    return;
                }
            }
        }
    };
    solve().catch(() => {
        statusElement.textContent = 'The automatic security check could not run. Please enable JavaScript and reload the page.';
    });
})();
</script>
</body>
</html>
HTML;
        exit;
    }

    public function sendHttpsRequired(): never
    {
        $this->headers(403);
        echo '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width, initial-scale=1">'
            . '<meta name="robots" content="noindex,nofollow"><title>HTTPS required</title></head>'
            . '<body><h1>HTTPS required</h1><p>This challenge requires HTTPS.</p></body></html>';
        exit;
    }

    public function sendUnavailable(): never
    {
        $this->headers(503);
        echo '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            . '<meta name="robots" content="noindex,nofollow"><title>Temporarily unavailable</title></head>'
            . '<body><h1>Temporarily unavailable</h1><p>Please try again shortly.</p></body></html>';
        exit;
    }

    private function headers(int $status): void
    {
        http_response_code($status);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Expires: 0');
        header('X-Robots-Tag: noindex, nofollow', true);
    }
}
