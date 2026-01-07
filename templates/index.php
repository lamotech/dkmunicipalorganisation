<?php

declare(strict_types=1);

use OCP\Util;

Util::addScript(OCA\DKMunicipalOrganisation\AppInfo\Application::APP_ID, OCA\DKMunicipalOrganisation\AppInfo\Application::APP_ID . '-main');
Util::addStyle(OCA\DKMunicipalOrganisation\AppInfo\Application::APP_ID, OCA\DKMunicipalOrganisation\AppInfo\Application::APP_ID . '-main');

?>

<div id="dkmunicipalorganisation"></div>
