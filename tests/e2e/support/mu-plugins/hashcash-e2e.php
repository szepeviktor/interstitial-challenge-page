<?php

declare(strict_types=1);

use SzepeViktor\WordPress\Waf\Config;
use SzepeViktor\WordPress\Waf\WordPress\MuPlugin;

defined('ABSPATH') || exit;

(new MuPlugin(Config::fromConstants()))->register();
