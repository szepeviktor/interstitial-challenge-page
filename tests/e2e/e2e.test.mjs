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

    server = spawn('/usr/bin/php', [
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
            PHP_CLI_SERVER_WORKERS: '4',
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

test('gate failures fail open only when explicitly configured', async () => {
    const failureHeaders = {
        ...browserHeaders,
        'X-HC-E2E-Gate-Failure': '1',
    };
    const failClosed = await client.request({
        path: '/wp-login.php',
        headers: failureHeaders,
    });

    assert.equal(failClosed.status, 500);
    assert.doesNotMatch(failClosed.text, /id=["']user_login["']/u);

    const failOpen = await client.request({
        path: '/wp-login.php',
        headers: {
            ...failureHeaders,
            'X-HC-E2E-Fail-Open': '1',
        },
    });

    assert.equal(failOpen.status, 200);
    assert.match(failOpen.text, /id=["']user_login["']/u);

    const recovered = await client.request({
        path: '/wp-login.php',
        headers: browserHeaders,
    });
    assert.equal(recovered.status, 200);
    assert.match(recovered.text, /id=["']user_login["']/u);
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
        const response = await page.goto(target + fragment, { waitUntil: 'domcontentloaded' });
        assert.equal(response?.status(), 429);
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
        const challenged = await page.goto('/browser-proof', { waitUntil: 'domcontentloaded' });
        assert.equal(challenged?.status(), 429);
        assert.equal((await challenged?.allHeaders())?.['hc-mitigated'], 'challenge');

        const redirect = page.waitForResponse(
            (response) => response.url().includes('/browser-proof') && response.status() === 303,
        );
        await page.locator('#hc_btn').click();
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

test('WordPress login issues an auth assertion and logout removes it', async () => {
    const context = await browser.newContext({ baseURL: baseUrl });
    const page = await context.newPage();

    try {
        const login = await page.goto('/wp-login.php', { waitUntil: 'domcontentloaded' });
        assert.notEqual(login?.status(), 429);

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

        const authOnlyContext = await browser.newContext({ baseURL: baseUrl });
        const wordpressOnlyContext = await browser.newContext({ baseURL: baseUrl });
        const tamperedContext = await browser.newContext({ baseURL: baseUrl });

        try {
            await authOnlyContext.addCookies([authAssertion]);
            await wordpressOnlyContext.addCookies(wordpressCookies);
            await tamperedContext.addCookies([
                ...wordpressCookies,
                {
                    ...authAssertion,
                    value: mutateLastCharacter(authAssertion.value),
                },
            ]);

            for (const attackContext of [
                authOnlyContext,
                wordpressOnlyContext,
                tamperedContext,
            ]) {
                const attackPage = await attackContext.newPage();
                const response = await attackPage.goto(
                    '/wp-config.php.backup',
                    { waitUntil: 'domcontentloaded' },
                );
                assert.equal(response?.status(), 429);
                assert.equal((await response?.allHeaders())?.['hc-mitigated'], 'challenge');
            }
        } finally {
            await Promise.all([
                authOnlyContext.close(),
                wordpressOnlyContext.close(),
                tamperedContext.close(),
            ]);
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

        cookies = await context.cookies();
        assert.equal(cookies.some((cookie) => cookie.name === 'hc_wp_auth'), false);

        const protectedAfterLogout = await page.goto(
            '/wp-config.php.backup',
            { waitUntil: 'domcontentloaded' },
        );
        assert.equal(protectedAfterLogout?.status(), 429);
        assert.equal((await protectedAfterLogout?.allHeaders())?.['hc-mitigated'], 'challenge');
    } finally {
        await context.close();
    }
}, { timeout: 45_000 });

function appendServerOutput(chunk) {
    serverOutput = (serverOutput + chunk.toString('utf8')).slice(-20_000);
}

function assertChallenge(response, context = '') {
    assert.equal(response.status, 429, context);
    assert.equal(header(response, 'hc-mitigated'), 'challenge', context);
    assert.match(response.text, /id="hc_btn"/u, context);
    assertUncacheableHtml(response, context);
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
        if (server.exitCode !== null) {
            throw new Error(`PHP server exited with ${server.exitCode}.\n${serverOutput}`);
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
