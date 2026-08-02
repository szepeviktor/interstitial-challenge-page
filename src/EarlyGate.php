<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf;

use SzepeViktor\WordPress\Waf\Challenge\ChallengeRenderer;
use SzepeViktor\WordPress\Waf\Challenge\ChallengeService;
use SzepeViktor\WordPress\Waf\Logging\RequestHeaderLogger;
use SzepeViktor\WordPress\Waf\Replay\NullReplayStore;
use SzepeViktor\WordPress\Waf\Replay\ReplayStore;
use SzepeViktor\WordPress\Waf\Scoring\DefaultScorer;
use SzepeViktor\WordPress\Waf\Scoring\Scorer;
use SzepeViktor\WordPress\Waf\Security\TokenService;
use Throwable;

final class EarlyGate
{
    private readonly Scorer $scorer;
    private readonly TokenService $tokenService;
    private readonly ChallengeService $challengeService;
    private readonly ChallengeRenderer $renderer;
    private readonly RequestHeaderLogger $requestHeaderLogger;
    private readonly RequestPolicy $requestPolicy;

    public function __construct(
        private readonly Config $config,
        ?Scorer $scorer = null,
        ?ReplayStore $replayStore = null,
    ) {
        $this->scorer = $scorer ?? new DefaultScorer();
        $this->tokenService = new TokenService($this->config->secret);
        $this->challengeService = new ChallengeService(
            $this->config,
            $this->tokenService,
            $replayStore ?? new NullReplayStore(),
        );
        $this->renderer = new ChallengeRenderer();
        $this->requestHeaderLogger = new RequestHeaderLogger($this->config->logPath);
        $this->requestPolicy = new RequestPolicy($this->config->requiredClearancePaths);
    }

    public function run(): void
    {
        $request = Request::fromGlobals($_SERVER, $_COOKIE, $_POST);

        try {
            $this->handle($request);
        } catch (Throwable $throwable) {
            error_log('WordPress WAF early gate: ' . $throwable->getMessage());

            if ($this->isChallengeSubmission($request)) {
                $this->renderer->sendUnavailable();
            }

            if (!$this->config->failOpen) {
                throw $throwable;
            }
        }
    }

    private function handle(Request $request): void
    {
        $now = time();

        if ($this->isChallengeSubmission($request)) {
            $stamp = $request->post['hc_stamp'];
            if (is_string($stamp) && $this->challengeService->verify($request, $stamp, $now)) {
                $this->setCookie(
                    name: $this->config->clearanceCookie,
                    value: $this->tokenService->issueClearance(
                        $request->host,
                        $now + $this->config->clearanceTtl,
                    ),
                    expires: $now + $this->config->clearanceTtl,
                    secure: true,
                );

                header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
                header('Location: ' . $request->target, true, 303);
                exit;
            }

            $this->sendChallenge($request, $now);
        }

        $decision = $this->requestPolicy->decide($request);
        if ($decision === RequestDecision::Bypass) {
            return;
        }

        if ($this->hasValidClearance($request, $now)) {
            return;
        }

        if ($decision === RequestDecision::RequireClearance) {
            $this->sendChallenge($request, $now);
        }

        if ($this->hasValidAuthAssertion($request, $now)) {
            return;
        }

        if (isset($request->cookies[$this->config->authCookie])) {
            $this->setCookie(
                name: $this->config->authCookie,
                value: '',
                expires: $now - 3600,
                secure: $request->scheme === 'https',
            );
        }

        $score = $this->scorer->score($request);
        $this->requestHeaderLogger->log($request, $score);
        if ($score->value < $this->config->challengeThreshold) {
            return;
        }

        $this->sendChallenge($request, $now);
    }

    private function sendChallenge(Request $request, int $now): never
    {
        if ($request->scheme !== 'https') {
            $this->renderer->sendHttpsRequired();
        }

        $this->renderer->send(
            $this->challengeService->create($request, $now),
            $request->target,
        );
    }

    private function isChallengeSubmission(Request $request): bool
    {
        return $request->method === 'POST'
            && ($request->post['hc_challenge'] ?? null) === '1'
            && isset($request->post['hc_stamp']);
    }

    private function hasValidClearance(Request $request, int $now): bool
    {
        $token = $request->cookies[$this->config->clearanceCookie] ?? '';

        return $this->tokenService->validateClearance(
            token: $token,
            host: $request->host,
            now: $now,
            maximumTtl: $this->config->clearanceTtl,
        );
    }

    private function hasValidAuthAssertion(Request $request, int $now): bool
    {
        $token = $request->cookies[$this->config->authCookie] ?? '';

        return $this->tokenService->validateAuthAssertion(
            token: $token,
            host: $request->host,
            wordpressCookies: $request->wordpressLoginCookies(),
            now: $now,
            maximumTtl: $this->config->authAssertionTtl,
        );
    }

    private function setCookie(
        string $name,
        string $value,
        int $expires,
        bool $secure,
    ): void {
        setcookie($name, $value, [
            'expires' => $expires,
            'path' => '/',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }
}
