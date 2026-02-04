<?php

declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Settings;

use OCA\DkMunicipalOrganisation\AppInfo\Application;
use OCA\DkMunicipalOrganisation\Db\CertificateRepository;
use OCA\DkMunicipalOrganisation\Service\Configuration;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Services\IInitialState;
use OCP\Settings\ISettings;

class AdminSettings implements ISettings {

	public function __construct(
		private Configuration $configuration,
		private CertificateRepository $certificateRepository,
		private IInitialState $initialState,
	) {
	}

	public function getForm(): TemplateResponse {
		$this->initialState->provideInitialState('config', $this->configuration->getAllConfigValues());

		$certificate = $this->certificateRepository->find('Primary');
		$this->initialState->provideInitialState('certificate', [
			'filepath' => $certificate['filepath'] ?? '',
			'password' => $certificate['password'] ?? '',
		]);

		\OCP\Util::addScript(Application::APP_ID, 'dkmunicipalorganisation-admin-settings');
		\OCP\Util::addStyle(Application::APP_ID, 'dkmunicipalorganisation-admin-settings');

		return new TemplateResponse(Application::APP_ID, 'settings-admin', [], '');
	}

	public function getSection(): string {
		return 'dkmunicipalorganisation';
	}

	public function getPriority(): int {
		return 10;
	}
}
