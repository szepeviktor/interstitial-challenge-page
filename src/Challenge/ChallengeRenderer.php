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
        $escapedBits = htmlspecialchars((string) $challenge->bits, ENT_QUOTES, 'UTF-8');

        $this->headers(429);
        header('HC-Mitigated: challenge');

        echo <<<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>One more step</title>
<style>
body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;padding:40px;background:#f7f7f7;color:#111}
.card{max-width:560px;margin:10vh auto;background:#fff;border:1px solid #ddd;border-radius:8px;padding:24px;box-shadow:0 4px 24px rgba(0,0,0,.08)}
button{background:#111;color:#fff;border:0;border-radius:6px;padding:10px 14px;font-size:14px;cursor:pointer}
code{background:#f0f0f0;padding:2px 6px;border-radius:4px}
</style>
</head>
<body>
<div class="card">
<h1>One more step</h1>
<p>We need a quick Hashcash proof-of-work.</p>
<p>Bits: <code>{$escapedBits}</code></p>
<form id="hc" method="post" action="{$escapedAction}">
<input type="hidden" name="hc_challenge" value="1">
<input type="hidden" name="hc_stamp" id="hc_stamp" value="">
<button type="button" id="hc_btn">Compute &amp; Continue</button>
<noscript><p>JavaScript is required.</p></noscript>
</form>
</div>
<script>
window.HC={$configuration};
(() => {
    const config = window.HC;
    const button = document.getElementById('hc_btn');
    const stampElement = document.getElementById('hc_stamp');
    const form = document.getElementById('hc');
    const toHex = (buffer) => Array.from(new Uint8Array(buffer))
        .map((value) => value.toString(16).padStart(2, '0')).join('');
    const sha1 = async (value) => toHex(
        await crypto.subtle.digest('SHA-1', new TextEncoder().encode(value))
    );
    const leadingZeroBits = (hex) => {
        let bits = 0;
        for (const character of hex) {
            const nibble = parseInt(character, 16);
            if (nibble === 0) { bits += 4; continue; }
            if (nibble >= 8) return bits;
            if (nibble >= 4) return bits + 1;
            if (nibble >= 2) return bits + 2;
            return bits + 3;
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
    button.addEventListener('click', async () => {
        button.disabled = true;
        button.textContent = 'Working...';
        const date = dateStamp();
        const random = randomValue();
        for (let counter = 0; ; counter += 1) {
            const encodedCounter = btoa(String(counter)).replace(/=+$/g, '');
            const stamp = `1:\${config.bits}:\${date}:\${config.resource}:\${config.token}:\${random}:\${encodedCounter}`;
            if (leadingZeroBits(await sha1(stamp)) >= config.bits) {
                stampElement.value = stamp;
                form.submit();
                return;
            }
            if (counter % 200 === 0) {
                await new Promise((resolve) => setTimeout(resolve, 0));
            }
        }
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
