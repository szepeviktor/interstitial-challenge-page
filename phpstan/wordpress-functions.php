<?php

final class WP_Error
{
    /** @return list<string> */
    public function get_error_codes(): array
    {
        return [];
    }

    /** @return list<string> */
    public function get_error_messages(string $code = ''): array
    {
        return [];
    }

    public function add(string $code, string $message, mixed $data = ''): void
    {
    }
}

function add_action(
    string $hookName,
    callable $callback,
    int $priority = 10,
    int $acceptedArgs = 1,
): true {
    return true;
}

function add_filter(
    string $hookName,
    callable $callback,
    int $priority = 10,
    int $acceptedArgs = 1,
): true {
    return true;
}

function is_user_logged_in(): bool
{
    return false;
}

function is_ssl(): bool
{
    return false;
}

function wp_login_url(string $redirect = '', bool $forceReauth = false): string
{
    return '';
}

function wp_safe_redirect(
    string $location,
    int $status = 302,
    string $xRedirectBy = 'WordPress',
): bool {
    return true;
}
