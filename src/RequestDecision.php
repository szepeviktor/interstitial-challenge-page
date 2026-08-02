<?php

declare(strict_types=1);

namespace SzepeViktor\WordPress\Waf;

enum RequestDecision
{
    case Bypass;
    case Normal;
    case RequireClearance;
}
