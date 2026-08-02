import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, before, test } from 'node:test';
import { chromium } from 'playwright-core';
import { solveChallenge, parseChallenge } from './hashcash.mjs';
import { firstCookie, formBody, HttpClient } from './http-client.mjs';
import { RedisClient } from './redis-client.mjs';

const repository = fileURLToPath(new URL('../..', import.meta.url));
const wordpress = process.env.HC_E2E_WORDPRESS_PATH ?? '/home/viktor/chatgpt-is-super';
const chrome = process.env.PLAYWRIGHT_CHROME_PATH ?? '/usr/bin/google-chrome';
const phpBinary = process.env.HC_E2E_PHP_BINARY ?? '/usr/bin/php';
const wordpressUser = process.env.HC_E2E_WP_USER ?? 'admin';
const wordpressPassword = process.env.HC_E2E_WP_PASSWORD ?? 'admin';
const redisHost = process.env.HC_E2E_REDIS_HOST ?? '127.0.0.1';
const redisPort = Number(process.env.HC_E2E_REDIS_PORT ?? 6379);
const runId = randomUUID().replaceAll('-', '');
const redisPrefix = `hashcash-e2e:${runId}:`;
const browserHeaders = {
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'User-Agent': 'Mozilla/5.0 Firefox/140.0',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
};

let baseUrl;
let browser;
let client;
let port;
let redis;
let server;
let serverOutput = '';

before(async () => {
    port = Number(process.env.HC_E2E_PORT ?? await freePort());
    baseUrl = `http://127.0.0.1:${port}`;
    client = new HttpClient({ port, authority: `127.0.0.1:${port}` });
    redis = new RedisClient({ host: redisHost, port: redisPort });
    assert.equal(await redis.command('PING'), 'PONG');

    server = spawn(phpBinary, [
        '-S',
        `127.0.0.1:${port}`,
        '-t',
        wordpress,
        join(repository, 'tests/e2e/support/router.php'),
    ], {
        cwd: wordpress,
        detached: true,
        env: {
            ...process.env,
            HC_E2E_REDIS_HOST: redisHost,
            HC_E2E_REDIS_PORT: String(redisPort),
            HC_E2E_RUN_ID: runId,
            HC_E2E_WORDPRESS_PATH: wordpress,
            PHP_CLI_SERVER_WORKERS: '2',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
    });

    server.stdout.on('data', appendServerOutput);
    server.stderr.on('data', appendServerOutput);

    await waitForServer();

    browser = await chromium.launch({
        executablePath: chrome,
        headless: true,
    });
}, { timeout: 30_000 });

after(async () => {
    await browser?.close();

    const serverFailure = server !== undefined && serverHasExited()
        ? new Error(
            `PHP server exited unexpectedly with code ${String(server.exitCode)}`
            + ` and signal ${String(server.signalCode)}.\nRecent PHP server output:\n`
            + serverOutput.slice(-4_000),
        )
        : null;

    if (server?.pid !== undefined) {
        try {
            process.kill(-server.pid, 'SIGTERM');
        } catch (error) {
            if (error.code !== 'ESRCH') {
                throw error;
            }
        }
    }

    await clearRedisKeys();

    if (serverFailure !== null) {
        throw serverFailure;
    }
});

test('ordinary and privacy-conscious document requests pass through', async () => {
    const ordinary = await client.request({ headers: browserHeaders });
    assertNotChallenge(ordinary);

    const privacyConscious = await client.request({
        headers: {
            Accept: browserHeaders.Accept,
            'User-Agent': browserHeaders['User-Agent'],
        },
    });
    assertNotChallenge(privacyConscious);
});

test('missing and scripted user agents are challenged', async () => {
    const { 'User-Agent': ignored, ...withoutUserAgent } = browserHeaders;
    const missing = await client.request({ headers: withoutUserAgent });
    assertChallenge(missing);

    const scripted = await client.request({
        headers: {
            ...browserHeaders,
            'User-Agent': 'curl/8.14.1',
        },
    });
    assertChallenge(scripted);
});

test('inconsistent Fetch Metadata is challenged while incomplete metadata remains below threshold', async () => {
    const inconsistent = await client.request({
        headers: {
            ...browserHeaders,
            'Sec-Fetch-Mode': 'cors',
        },
    });
    assertChallenge(inconsistent);

    const incomplete = await client.request({
        headers: {
            Accept: browserHeaders.Accept,
            'Accept-Language': browserHeaders['Accept-Language'],
            'User-Agent': browserHeaders['User-Agent'],
            'Sec-Fetch-Dest': 'document',
        },
    });
    assertNotChallenge(incomplete);
});

test('sensitive-file and encoded traversal probes are challenged', async () => {
    for (const path of [
        '/.env',
        '/.git/config',
        '/wp-config.php.bak',
        '/wp-content/%2e%2e/wp-config.php',
        '/wp-content/%252e%252e/wp-config.php',
        '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
    ]) {
        const response = await client.request({ path, headers: browserHeaders });
        assertChallenge(response, path);
    }
});

test('non-document and excluded WordPress requests bypass scoring', async () => {
    const api = await client.request({
        path: '/?rest_route=/',
        headers: {
            Accept: 'application/json',
            'User-Agent': 'curl/8.14.1',
        },
    });
    assertNotChallenge(api);

    const excluded = await client.request({
        path: '/wp-json/',
        headers: {
            ...browserHeaders,
            'User-Agent': 'curl/8.14.1',
        },
    });
    assertNotChallenge(excluded);
});

test('checkout and WordPress login require a completed challenge', async () => {
    for (const path of [
        '/checkout',
        '/checkout/',
        '/wp-login.php?redirect_to=%2Fwp-admin%2F',
        '/wp-login.php?wc-ajax=checkout',
    ]) {
        const response = await client.request({ path, headers: browserHeaders });
        assertChallenge(response, path);
        assert.match(response.text, /quick check helps protect the site/u);
        assert.doesNotMatch(response.text, /<button/u);
    }

    const directLogin = await client.request({
        method: 'POST',
        path: '/wp-login.php',
        headers: {
            ...browserHeaders,
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: formBody({ log: wordpressUser, pwd: wordpressPassword }),
    });
    assertChallenge(directLogin, 'direct WordPress login POST');

    const similarlyNamed = await client.request({
        path: '/checkout-later',
        headers: browserHeaders,
    });
    assertNotChallenge(similarlyNamed);

    const wcAjax = await client.request({
        path: '/checkout?wc-ajax=checkout',
        headers: browserHeaders,
    });
    assertNotChallenge(wcAjax);

    const target = '/checkout?coupon=welcome';
    const challenged = await client.request({ path: target, headers: browserHeaders });
    const submission = await submitStamp(target, solveChallenge(parseChallenge(challenged.text)));
    assertClearanceRedirect(submission, target);

    const clearance = firstCookie(submission, 'hc_clearance');
    const clearedCheckout = await client.request({
        path: target,
        headers: { ...browserHeaders, Cookie: clearance },
    });
    assertNotChallenge(clearedCheckout);

    const clearedLogin = await client.request({
        path: '/wp-login.php',
        headers: { ...browserHeaders, Cookie: clearance },
    });
    assert.equal(clearedLogin.status, 200);
    assert.match(clearedLogin.text, /id=["']user_login["']/u);
});

test('gate failures fail open only when explicitly configured', async () => {
    const failureHeaders = {
        ...browserHeaders,
        'X-HC-E2E-Gate-Failure': '1',
    };
    const failClosed = await client.request({
        path: '/',
        headers: failureHeaders,
    });

    assert.equal(failClosed.status, 500);

    const failOpen = await client.request({
        path: '/',
        headers: {
            ...failureHeaders,
            'X-HC-E2E-Fail-Open': '1',
        },
    });

    assert.equal(failOpen.status, 200);
    assert.equal(header(failOpen, 'hc-mitigated'), '');

    const recovered = await client.request({
        path: '/',
        headers: browserHeaders,
    });
    assert.equal(recovered.status, 200);
    assert.equal(header(recovered, 'hc-mitigated'), '');
});

test('HTTP challenge candidates receive 403 without the mitigation header', async () => {
    const response = await client.request({
        headers: {
            ...browserHeaders,
            'User-Agent': 'curl/8.14.1',
            'X-HC-E2E-HTTPS': 'off',
        },
    });

    assert.equal(response.status, 403);
    assert.equal(header(response, 'hc-mitigated'), '');
    assert.match(response.text, /HTTPS required/u);
    assertUncacheableHtml(response);
});

test('proof submission issues clearance, binds it to the host, and rejects replay', async () => {
    const target = '/proof-target?next=%2F';
    const challenged = await client.request({
        path: target,
        headers: {
            ...browserHeaders,
            'User-Agent': 'curl/8.14.1',
        },
    });
    assertChallenge(challenged);

    const challenge = parseChallenge(challenged.text);
    const stamp = solveChallenge(challenge);
    const body = formBody({ hc_challenge: '1', hc_stamp: stamp });
    const submission = await client.request({
        method: 'POST',
        path: target,
        headers: {
            Accept: browserHeaders.Accept,
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body,
    });

    assertClearanceRedirect(submission, target);

    const ttl = await redis.command('TTL', replayKey(challenge));
    assert.ok(ttl > 0 && ttl <= 60, `Unexpected replay TTL: ${ttl}`);

    const clearance = firstCookie(submission, 'hc_clearance');
    assert.notEqual(clearance, '');

    const cleared = await client.request({
        path: target,
        headers: {
            ...browserHeaders,
            Cookie: clearance,
            'User-Agent': 'curl/8.14.1',
        },
    });
    assertNotChallenge(cleared);

    const wrongHost = await client.request({
        path: target,
        headers: {
            ...browserHeaders,
            Host: `other.test:${port}`,
            Cookie: clearance,
            'User-Agent': 'curl/8.14.1',
        },
    });
    assertChallenge(wrongHost);

    const tamperedClearance = `${clearance.slice(0, -1)}${clearance.endsWith('a') ? 'b' : 'a'}`;
    const tampered = await client.request({
        path: target,
        headers: {
            ...browserHeaders,
            Cookie: tamperedClearance,
            'User-Agent': 'curl/8.14.1',
        },
    });
    assertChallenge(tampered);

    const replay = await client.request({
        method: 'POST',
        path: target,
        headers: {
            Accept: browserHeaders.Accept,
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body,
    });
    assertChallenge(replay);
});

test('an atomic replay claim allows exactly one concurrent proof submission', async () => {
    const target = '/concurrent-replay';
    const challenged = await client.request({
        path: target,
        headers: {
            ...browserHeaders,
            'User-Agent': 'curl/8.14.1',
        },
    });
    const stamp = solveChallenge(parseChallenge(challenged.text));
    const body = formBody({ hc_challenge: '1', hc_stamp: stamp });
    const submissions = await Promise.all(
        Array.from({ length: 12 }, () => client.request({
            method: 'POST',
            path: target,
            headers: {
                Accept: browserHeaders.Accept,
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body,
        })),
    );
    const successful = submissions.filter((response) => response.status === 303);
    const rejected = submissions.filter((response) => response.status === 429);

    assert.equal(successful.length, 1);
    assert.equal(rejected.length, 11);

    for (const response of rejected) {
        assert.equal(header(response, 'hc-mitigated'), 'challenge');
    }
});

test('the replay contract tests fail when NullReplayStore is substituted', {
    skip: process.env.HC_E2E_MUTATION_CHILD === '1',
}, async () => {
    const pattern = [
        '^(',
        'proof submission issues clearance, binds it to the host, and rejects replay',
        '|an atomic replay claim allows exactly one concurrent proof submission',
        ')$',
    ].join('');
    const mutation = await runNodeTestMutation(pattern, {
        HC_E2E_MUTATION_CHILD: '1',
        HC_E2E_REPLAY_STORE: 'null',
    });

    assert.equal(mutation.code, 1, mutation.output);
    assert.match(
        mutation.output,
        /not ok \d+ - proof submission issues clearance, binds it to the host, and rejects replay/u,
    );
    assert.match(
        mutation.output,
        /not ok \d+ - an atomic replay claim allows exactly one concurrent proof submission/u,
    );
});

test('malformed and tampered stamps are rejected without consuming the original challenge', async () => {
    const target = '/stamp-tampering';
    const challenged = await client.request({
        path: target,
        headers: {
            ...browserHeaders,
            'User-Agent': 'curl/8.14.1',
        },
    });
    const stamp = solveChallenge(parseChallenge(challenged.text));
    const parts = stamp.split(':');
    const tokenParts = parts[4].split('.');
    tokenParts[3] = mutateLastCharacter(tokenParts[3]);

    const attacks = [
        ['wrong version', ['2', ...parts.slice(1)].join(':')],
        ['wrong difficulty', [parts[0], '7', ...parts.slice(2)].join(':')],
        ['malformed date', [parts[0], parts[1], '000000000000', ...parts.slice(3)].join(':')],
        ['wrong resource', [...parts.slice(0, 3), 'different-resource', ...parts.slice(4)].join(':')],
        ['tampered signature', [...parts.slice(0, 4), tokenParts.join('.'), ...parts.slice(5)].join(':')],
        ['empty random value', [...parts.slice(0, 5), '', parts[6]].join(':')],
        ['empty counter', [...parts.slice(0, 6), ''].join(':')],
        ['extra field', `${stamp}:extra`],
    ];

    for (const [name, attackedStamp] of attacks) {
        const response = await submitStamp(target, attackedStamp);
        assertChallenge(response, name);
    }

    const arrayStamp = await client.request({
        method: 'POST',
        path: target,
        headers: {
            Accept: browserHeaders.Accept,
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'hc_challenge=1&hc_stamp%5B%5D=not-a-string',
    });
    assertChallenge(arrayStamp, 'array stamp');

    const original = await submitStamp(target, stamp);
    assert.equal(original.status, 303);
});

test('proofs are bound to scheme, authority, path, and exact query ordering', async () => {
    const target = '/binding?a=1&b=2';
    const challenged = await client.request({
        path: target,
        headers: {
            ...browserHeaders,
            'User-Agent': 'curl/8.14.1',
        },
    });
    const stamp = solveChallenge(parseChallenge(challenged.text));

    assertChallenge(await submitStamp('/binding?b=2&a=1', stamp), 'query ordering');
    assertChallenge(
        await submitStamp(target, stamp, { Host: `different.test:${port}` }),
        'authority',
    );

    const downgraded = await submitStamp(target, stamp, { 'X-HC-E2E-HTTPS': 'off' });
    assert.equal(downgraded.status, 403);
    assert.equal(header(downgraded, 'hc-mitigated'), '');

    const exact = await submitStamp(target, stamp);
    assert.equal(exact.status, 303);
});

test('a replay-store failure returns 503 and does not consume the proof', async () => {
    const target = '/replay-store-failure';
    const challenged = await client.request({
        path: target,
        headers: {
            ...browserHeaders,
            'User-Agent': 'curl/8.14.1',
        },
    });
    const stamp = solveChallenge(parseChallenge(challenged.text));
    const unavailable = await submitStamp(target, stamp, {
        'X-HC-E2E-Replay-Failure': '1',
    });

    assert.equal(unavailable.status, 503);
    assert.equal(header(unavailable, 'hc-mitigated'), '');
    assert.match(unavailable.text, /Temporarily unavailable/u);
    assert.doesNotMatch(
        unavailable.text,
        /Simulated Redis SET failure|RedisException|Stack trace|Fatal error/iu,
    );
    assertUncacheableHtml(unavailable);

    const recovered = await submitStamp(target, stamp);
    assert.equal(recovered.status, 303);
});

test('a proof cannot be submitted for a different resource', async () => {
    const challenged = await client.request({
        path: '/proof-for-one-resource',
        headers: {
            ...browserHeaders,
            'User-Agent': 'curl/8.14.1',
        },
    });
    const stamp = solveChallenge(parseChallenge(challenged.text));
    const response = await client.request({
        method: 'POST',
        path: '/different-resource',
        headers: {
            Accept: browserHeaders.Accept,
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: formBody({ hc_challenge: '1', hc_stamp: stamp }),
    });

    assertChallenge(response);
});

test('a network-path request can only redirect to a local absolute path', async () => {
    const requestTarget = '//attacker.example/landing';
    const challenged = await client.request({
        path: requestTarget,
        headers: {
            ...browserHeaders,
            'User-Agent': 'curl/8.14.1',
        },
    });
    const stamp = solveChallenge(parseChallenge(challenged.text));
    const submission = await submitStamp(requestTarget, stamp);

    assert.equal(submission.status, 303);
    assert.equal(header(submission, 'location'), '/attacker.example/landing');
    assertLocalRedirect(submission);
});

test('hostile request targets cannot inject markup, script, headers, or external redirects', async () => {
    const payload = encodeURIComponent(
        '"><script>globalThis.__hashcashInjected="yes"</script> ☃',
    );
    const target = `/hostile-target?next=${payload}`
        + '&slashes=%5C%5Cattacker.example'
        + '&line=%0D%0AX-HC-Injected%3A%20yes';
    const fragment = '#%22%3E%3Cscript%3EglobalThis.__hashcashFragmentInjected%3D%22yes%22';
    const challenged = await client.request({
        path: target,
        headers: {
            ...browserHeaders,
            'User-Agent': 'curl/8.14.1',
        },
    });

    assertChallenge(challenged);
    assert.equal(header(challenged, 'x-hc-injected'), '');
    assert.doesNotMatch(challenged.text, /<script>globalThis\.__hashcashInjected/u);

    const context = await browser.newContext({
        baseURL: baseUrl,
        userAgent: 'curl/8.14.1',
    });
    const page = await context.newPage();

    try {
        await page.addInitScript(() => {
            HTMLFormElement.prototype.submit = function submit() {
                globalThis.__hashcashSubmitted = true;
            };
        });
        const response = await page.goto(target + fragment, { waitUntil: 'domcontentloaded' });
        assert.equal(response?.status(), 429);
        await page.waitForFunction(() => globalThis.__hashcashSubmitted === true);
        assert.equal(await page.locator('#hc').getAttribute('action'), target);
        assert.equal(
            await page.evaluate(() => globalThis.__hashcashInjected),
            undefined,
        );
        assert.equal(
            await page.evaluate(() => globalThis.__hashcashFragmentInjected),
            undefined,
        );
    } finally {
        await context.close();
    }

    const stamp = solveChallenge(parseChallenge(challenged.text));
    const submission = await submitStamp(target, stamp);

    assertClearanceRedirect(submission, target);
    assert.equal(header(submission, 'x-hc-injected'), '');
});

test('installed Chrome solves the JavaScript challenge and retains clearance', async () => {
    const context = await browser.newContext({
        baseURL: baseUrl,
        userAgent: 'curl/8.14.1',
    });
    const page = await context.newPage();

    try {
        const challengedPromise = page.waitForResponse(
            (response) => response.url().includes('/browser-proof') && response.status() === 429,
        );
        const redirect = page.waitForResponse(
            (response) => response.url().includes('/browser-proof') && response.status() === 303,
        );
        const challenged = await page.goto('/browser-proof', { waitUntil: 'domcontentloaded' });
        const challengedResponse = await challengedPromise;
        assert.equal(challengedResponse.status(), 429);
        assert.equal((await challengedResponse.allHeaders())['hc-mitigated'], 'challenge');
        assert.ok(challenged === null || challenged.status() === 429);
        await redirect;
        await page.waitForLoadState('domcontentloaded');

        const clearance = (await context.cookies()).find((cookie) => cookie.name === 'hc_clearance');
        assert.ok(clearance);
        assert.equal(clearance.httpOnly, true);
        assert.equal(clearance.secure, true);
        assert.equal(clearance.sameSite, 'Lax');

        const cleared = await page.goto('/browser-proof', { waitUntil: 'domcontentloaded' });
        assert.notEqual(cleared?.status(), 429);
        assert.equal((await cleared?.allHeaders())?.['hc-mitigated'], undefined);
    } finally {
        await context.close();
    }
}, { timeout: 30_000 });

test('a failed WordPress login shows its error after a fresh challenge', async () => {
    const context = await browser.newContext({ baseURL: baseUrl });
    const page = await context.newPage();

    try {
        const challengedPromise = page.waitForResponse(
            (response) => response.url().includes('/wp-login.php') && response.status() === 429,
        );
        const clearanceRedirect = page.waitForResponse(
            (response) => response.url().includes('/wp-login.php') && response.status() === 303,
        );
        await page.goto('/wp-login.php', { waitUntil: 'domcontentloaded' });
        await challengedPromise;
        await clearanceRedirect;
        await page.waitForLoadState('domcontentloaded');

        assert.ok(
            (await context.cookies()).some((cookie) => cookie.name === 'hc_clearance'),
        );

        await page.locator('#user_login').fill(wordpressUser);
        await page.locator('#user_pass').fill('deliberately-incorrect-e2e-password');
        const failedLoginRedirectPromise = page.waitForResponse(
            (response) => response.url().includes('/wp-login.php')
                && response.request().method() === 'POST'
                && response.status() === 303,
        );
        const rechallengedPromise = page.waitForResponse(
            (response) => response.url().includes('/wp-login.php') && response.status() === 429,
        );
        const challengeSubmissionPromise = page.waitForResponse(
            (response) => response.url().includes('/wp-login.php')
                && response.request().method() === 'POST'
                && response.request().postData()?.includes('hc_challenge=1') === true
                && response.status() === 303,
        );
        await page.locator('#wp-submit').click();

        const failedLoginRedirect = await failedLoginRedirectPromise;
        const rechallenged = await rechallengedPromise;
        await challengeSubmissionPromise;
        await page.waitForLoadState('domcontentloaded');

        const failedLoginHeaders = await failedLoginRedirect.allHeaders();
        const failedLoginLocation = new URL(failedLoginHeaders.location, baseUrl);
        assert.equal(failedLoginLocation.pathname, '/wp-login.php');
        assert.equal(failedLoginLocation.searchParams.has('hc_login_failed'), false);
        assert.match(
            failedLoginHeaders['set-cookie'],
            /hc_clearance=(?:deleted)?;.*(?:expires=|max-age=0)/iu,
        );
        assert.match(failedLoginHeaders['set-cookie'], /hc_login_error=/u);
        assert.equal((await rechallenged.allHeaders())['hc-mitigated'], 'challenge');
        await page.locator('#login_error').waitFor();
        assert.match(
            await page.locator('#login_error').innerText(),
            new RegExp(
                `The password you entered for the username ${wordpressUser} is incorrect\\.`,
                'u',
            ),
        );

        const cookies = await context.cookies();
        assert.equal(cookies.some((cookie) => cookie.name === 'hc_clearance'), true);
        assert.equal(cookies.some((cookie) => cookie.name === 'hc_login_error'), false);
        assert.equal(
            cookies.some((cookie) => cookie.name.startsWith('wordpress_logged_in_')),
            false,
        );
        assert.equal(cookies.some((cookie) => cookie.name === 'hc_wp_auth'), false);
    } finally {
        await context.close();
    }
}, { timeout: 30_000 });

test('WordPress login issues an auth assertion and logout removes it', async () => {
    const context = await browser.newContext({ baseURL: baseUrl });
    const page = await context.newPage();

    try {
        const challengedPromise = page.waitForResponse(
            (response) => response.url().includes('/wp-login.php') && response.status() === 429,
        );
        const clearanceRedirect = page.waitForResponse(
            (response) => response.url().includes('/wp-login.php') && response.status() === 303,
        );
        const login = await page.goto('/wp-login.php', { waitUntil: 'domcontentloaded' });
        const challenged = await challengedPromise;
        assert.equal(challenged.status(), 429);
        assert.ok(login === null || login.status() === 429);
        await clearanceRedirect;
        await page.waitForLoadState('domcontentloaded');

        await page.locator('#user_login').fill(wordpressUser);
        await page.locator('#user_pass').fill(wordpressPassword);
        await Promise.all([
            page.waitForNavigation({ waitUntil: 'domcontentloaded' }),
            page.locator('#wp-submit').click(),
        ]);

        let cookies = await context.cookies();
        const wordpressCookies = cookies.filter(
            (cookie) => cookie.name.startsWith('wordpress_logged_in_'),
        );
        const authAssertion = cookies.find((cookie) => cookie.name === 'hc_wp_auth');
        assert.ok(wordpressCookies.length > 0);
        assert.ok(authAssertion);
        assert.ok(cookies.some((cookie) => cookie.name === 'hc_clearance'));

        await page.goto('about:blank', { waitUntil: 'commit' });

        const probeContext = await browser.newContext({ baseURL: baseUrl });
        try {
            const probePage = await probeContext.newPage();
            const probes = [
                {
                    name: 'auth assertion without a WordPress cookie',
                    cookies: [authAssertion],
                },
                {
                    name: 'WordPress cookie without an auth assertion',
                    cookies: wordpressCookies,
                },
                {
                    name: 'tampered auth assertion',
                    cookies: [
                        ...wordpressCookies,
                        {
                            ...authAssertion,
                            value: mutateLastCharacter(authAssertion.value),
                        },
                    ],
                },
            ];

            for (const probe of probes) {
                await probeContext.clearCookies();
                await probeContext.addCookies(probe.cookies);

                const response = await gotoChromeProbe(
                    probePage,
                    '/wp-config.php.backup',
                    probe.name,
                );
                assert.equal(response?.status(), 429, probe.name);
                assert.equal(
                    (await response?.allHeaders())?.['hc-mitigated'],
                    'challenge',
                    probe.name,
                );

                await probePage.goto('about:blank', { waitUntil: 'commit' });
            }

            await probeContext.clearCookies();
            await probeContext.addCookies([...wordpressCookies, authAssertion]);
            const mandatory = await gotoChromeProbe(
                probePage,
                '/checkout',
                'authenticated session without challenge clearance',
            );
            assert.equal(mandatory?.status(), 429);
            assert.equal((await mandatory?.allHeaders())?.['hc-mitigated'], 'challenge');
        } finally {
            await probeContext.close();
        }

        const protectedWhileAuthenticated = await page.goto(
            '/wp-config.php.backup',
            { waitUntil: 'domcontentloaded' },
        );
        assert.notEqual(protectedWhileAuthenticated?.status(), 429);
        assert.equal((await protectedWhileAuthenticated?.allHeaders())?.['hc-mitigated'], undefined);

        await page.goto('/wp-admin/', { waitUntil: 'domcontentloaded' });
        const logoutUrl = await page.locator('#wp-admin-bar-logout a').getAttribute('href');
        assert.ok(logoutUrl);
        await page.goto(logoutUrl, { waitUntil: 'domcontentloaded' });

        await context.clearCookies({ name: 'hc_clearance' });
        const protectedAfterLogout = await page.goto(
            '/wp-config.php.backup',
            { waitUntil: 'domcontentloaded' },
        );
        assert.equal(protectedAfterLogout?.status(), 429);
        assert.equal((await protectedAfterLogout?.allHeaders())?.['hc-mitigated'], 'challenge');

        cookies = await context.cookies();
        assert.equal(cookies.some((cookie) => cookie.name === 'hc_wp_auth'), false);
    } finally {
        await context.close();
    }
}, { timeout: 45_000 });

function appendServerOutput(chunk) {
    serverOutput = (serverOutput + chunk.toString('utf8')).slice(-20_000);
}

async function gotoChromeProbe(page, path, scenario) {
    try {
        return await page.goto(path, {
            waitUntil: 'commit',
            timeout: 10_000,
        });
    } catch (error) {
        throw new Error(
            `Chrome probe failed for "${scenario}".\nRecent PHP server output:\n${serverOutput.slice(-4_000)}`,
            { cause: error },
        );
    }
}

function assertChallenge(response, context = '') {
    const diagnostics = [
        context,
        `Response body:\n${response.text.slice(-2_000)}`,
        `Recent PHP server output:\n${serverOutput.slice(-4_000)}`,
    ].filter(Boolean).join('\n');

    assert.equal(response.status, 429, diagnostics);
    assert.equal(header(response, 'hc-mitigated'), 'challenge', diagnostics);
    assert.match(response.text, /id="hc_status"/u, diagnostics);
    assertUncacheableHtml(response, diagnostics);
}

function assertNotChallenge(response) {
    assert.notEqual(response.status, 429);
    assert.equal(header(response, 'hc-mitigated'), '');
}

function header(response, name) {
    return response.headers[name.toLowerCase()]?.[0] ?? '';
}

function assertUncacheableHtml(response, context = '') {
    assert.equal(header(response, 'content-type'), 'text/html; charset=utf-8', context);
    assert.equal(
        header(response, 'cache-control'),
        'no-store, no-cache, must-revalidate, max-age=0',
        context,
    );
    assert.equal(header(response, 'pragma'), 'no-cache', context);
    assert.equal(header(response, 'expires'), '0', context);
    assert.equal(header(response, 'x-robots-tag'), 'noindex, nofollow', context);
}

function assertClearanceRedirect(response, expectedTarget) {
    assert.equal(response.status, 303);
    assert.equal(header(response, 'location'), expectedTarget);
    assert.equal(header(response, 'hc-mitigated'), '');
    assert.match(header(response, 'cache-control'), /(?:^|,\s*)no-store(?:,|$)/u);
    assertLocalRedirect(response);

    const clearance = (response.headers['set-cookie'] ?? [])
        .find((cookie) => cookie.startsWith('hc_clearance='));

    assert.ok(clearance);
    assert.match(clearance, /;\s*path=\//iu);
    assert.match(clearance, /;\s*secure(?:;|$)/iu);
    assert.match(clearance, /;\s*httponly(?:;|$)/iu);
    assert.match(clearance, /;\s*samesite=lax(?:;|$)/iu);
}

function assertLocalRedirect(response) {
    const location = header(response, 'location');

    assert.ok(location.startsWith('/'));
    assert.equal(new URL(location, baseUrl).origin, baseUrl);
}

function submitStamp(path, stamp, headers = {}) {
    return client.request({
        method: 'POST',
        path,
        headers: {
            Accept: browserHeaders.Accept,
            'Content-Type': 'application/x-www-form-urlencoded',
            ...headers,
        },
        body: formBody({ hc_challenge: '1', hc_stamp: stamp }),
    });
}

function mutateLastCharacter(value) {
    return `${value.slice(0, -1)}${value.endsWith('a') ? 'b' : 'a'}`;
}

function replayKey(challenge) {
    const tokenParts = challenge.token.split('.');
    const nonce = tokenParts[2];

    return redisPrefix + createHash('sha256').update(nonce).digest('hex');
}

async function clearRedisKeys() {
    if (redis === undefined) {
        return;
    }

    let cursor = '0';

    do {
        const response = await redis.command('SCAN', cursor, 'MATCH', `${redisPrefix}*`, 'COUNT', 100);
        cursor = response[0];
        const keys = response[1];

        if (keys.length > 0) {
            await redis.command('DEL', ...keys);
        }
    } while (cursor !== '0');
}

function runNodeTestMutation(pattern, environment) {
    return new Promise((resolve, reject) => {
        const childEnvironment = {
            ...process.env,
            ...environment,
        };
        delete childEnvironment.NODE_TEST_CONTEXT;

        const child = spawn(process.execPath, [
            '--test',
            '--test-concurrency=1',
            '--test-reporter=tap',
            `--test-name-pattern=${pattern}`,
            join(repository, 'tests/e2e/e2e.test.mjs'),
        ], {
            cwd: repository,
            env: childEnvironment,
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        let output = '';

        child.stdout.on('data', (chunk) => {
            output += chunk.toString('utf8');
        });
        child.stderr.on('data', (chunk) => {
            output += chunk.toString('utf8');
        });
        child.on('error', reject);
        child.on('exit', (code, signal) => {
            if (signal !== null) {
                reject(new Error(`Mutation test exited via ${signal}.\n${output}`));
                return;
            }

            resolve({ code, output });
        });
    });
}

async function waitForServer() {
    for (let attempt = 0; attempt < 100; attempt += 1) {
        if (serverHasExited()) {
            throw new Error(
                `PHP server exited with code ${String(server.exitCode)}`
                + ` and signal ${String(server.signalCode)}.\n${serverOutput}`,
            );
        }

        try {
            await client.request({
                headers: browserHeaders,
                timeout: 500,
            });
            return;
        } catch {
            await new Promise((resolve) => setTimeout(resolve, 100));
        }
    }

    throw new Error(`PHP server did not become ready.\n${serverOutput}`);
}

function serverHasExited() {
    return server.exitCode !== null || server.signalCode !== null;
}

function freePort() {
    return new Promise((resolve, reject) => {
        const temporaryServer = createServer();
        temporaryServer.unref();
        temporaryServer.on('error', reject);
        temporaryServer.listen(0, '127.0.0.1', () => {
            const address = temporaryServer.address();

            if (typeof address !== 'object' || address === null) {
                temporaryServer.close();
                reject(new Error('Unable to allocate an E2E port.'));
                return;
            }

            temporaryServer.close((error) => {
                if (error) {
                    reject(error);
                    return;
                }

                resolve(address.port);
            });
        });
    });
}
