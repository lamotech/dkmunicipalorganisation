<?php

declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Settings;

use OCA\DkMunicipalOrganisation\AppInfo\Application;
use OCA\DkMunicipalOrganisation\Db\CertificateRepository;
use OCA\DkMunicipalOrganisation\Db\OrgSyncLogRepository;
use OCA\DkMunicipalOrganisation\Service\Configuration;
use OCP\App\IAppManager;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Services\IInitialState;
use OCP\Settings\ISettings;

class AdminSettings implements ISettings {

	public function __construct(
		private Configuration $configuration,
		private CertificateRepository $certificateRepository,
		private OrgSyncLogRepository $orgSyncLogRepository,
		private IInitialState $initialState,
		private IAppManager $appManager,
	) {
	}

	public function getForm(): TemplateResponse {
		$this->initialState->provideInitialState('prerequisites', [
			'groupfolders' => $this->appManager->isEnabledForUser('groupfolders'),
		]);

		$this->initialState->provideInitialState('config', $this->configuration->getAllConfigValues());

		$certificate = $this->certificateRepository->find('Primary');
		$this->initialState->provideInitialState('certificate', [
			'filepath' => $certificate['filepath'] ?? '',
			'password' => $certificate['password'] ?? '',
		]);

		$this->initialState->provideInitialState('syncLog', $this->orgSyncLogRepository->findLatest(5));

		\OCP\Util::addTranslations(Application::APP_ID);
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
