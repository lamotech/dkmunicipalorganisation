<?php

declare(strict_types=1);

use OCP\Util;

Util::addScript(OCA\DkMunicipalOrganisation\AppInfo\Application::APP_ID, OCA\DkMunicipalOrganisation\AppInfo\Application::APP_ID . '-main');
Util::addStyle(OCA\DkMunicipalOrganisation\AppInfo\Application::APP_ID, OCA\DkMunicipalOrganisation\AppInfo\Application::APP_ID . '-main');

?>

<div id="dkmunicipalorganisation"></div>
