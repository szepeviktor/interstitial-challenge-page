<?php

declare(strict_types=1);

use SzepeViktor\WordPress\Waf\Config;
use SzepeViktor\WordPress\Waf\WordPress\MuPlugin;

defined('ABSPATH') || exit;

/*
 * HASHCASH_INTERSTITIAL_SECRET was defined in wp-config.php. The MU plugin
 * shares that dedicated key with the early gate so its authentication
 * assertions can be verified before WordPress boots on subsequent requests.
 */
(new MuPlugin(Config::fromConstants()))->register();
