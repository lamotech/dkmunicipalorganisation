<?php

namespace OCA\DkMunicipalOrganisation\BackgroundJob;

use OCP\BackgroundJob\TimedJob;
use OCP\AppFramework\Utility\ITimeFactory;
use OCA\DkMunicipalOrganisation\Service\Configuration;
use OCA\DkMunicipalOrganisation\Service\OrganisationSyncService;
use Psr\Log\LoggerInterface;

class SyncOrganisationsJob extends TimedJob {
	public function __construct(
		ITimeFactory $time,
		private OrganisationSyncService $organisationSyncService,
		private Configuration $configuration,
		private LoggerInterface $logger,
	) {
		parent::__construct($time);
		$this->setInterval(24 * 60 * 60);
	}

	protected function run($argument): void {
		if ($this->configuration->getConfigValue('organisation_enable', '0') !== '1') {
			$this->logger->debug('Org sync skipped: organisation not enabled', ['app' => 'dkmunicipalorganisation']);
			return;
		}

		try {
			$res = $this->organisationSyncService->sync();
			$this->logger->info('Org sync finished', ['app' => 'dkmunicipalorganisation'] + $res);
		} catch (\Throwable $e) {
			$this->logger->error('Org sync failed: ' . $e->getMessage(), [
				'app' => 'dkmunicipalorganisation',
				'exception' => $e,
			]);
		}
	}
}
