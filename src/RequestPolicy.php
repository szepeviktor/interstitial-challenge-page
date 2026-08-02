<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf;

final class RequestPolicy
{
    /**
     * @param list<string> $requiredClearancePaths
     */
    public function __construct(private readonly array $requiredClearancePaths)
    {
    }

    public function decide(Request $request): RequestDecision
    {
        if ($this->requiresClearance($request)) {
            return RequestDecision::RequireClearance;
        }

        if (!$request->isHtmlDocumentNavigation() || $this->isExcludedWordPressRequest($request)) {
            return RequestDecision::Bypass;
        }

        return RequestDecision::Normal;
    }

    private function requiresClearance(Request $request): bool
    {
        if (!in_array($request->path, $this->requiredClearancePaths, true)) {
            return false;
        }

        if ($request->isHtmlDocumentNavigation()) {
            return !$this->isWooCommerceCheckoutAjaxRequest($request);
        }

        return $request->path === '/wp-login.php' && $request->method === 'POST';
    }

    private function isExcludedWordPressRequest(Request $request): bool
    {
        return $request->path === '/wp-admin/admin-ajax.php'
            || $request->path === '/wp-admin/admin-post.php'
            || $request->path === '/wp-cron.php'
            || $request->path === '/xmlrpc.php'
            || $request->path === '/robots.txt'
            || $request->path === '/favicon.ico'
            || $request->path === '/wp-sitemap.xml'
            || str_starts_with($request->path, '/wp-json/');
    }

    private function isWooCommerceCheckoutAjaxRequest(Request $request): bool
    {
        return ($request->path === '/checkout' || $request->path === '/checkout/')
            && preg_match('/(?:^|[?&])wc-ajax=/i', $request->target) === 1;
    }
}
