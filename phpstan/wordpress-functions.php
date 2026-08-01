<?php

function add_action(
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
