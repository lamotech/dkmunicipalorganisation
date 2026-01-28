<?php

namespace OCA\DkMunicipalOrganisation\BackgroundJob;

use OCP\BackgroundJob\TimedJob;
use OCP\AppFramework\Utility\ITimeFactory;
use OCA\DkMunicipalOrganisation\Service\OrganisationSyncService;
use Psr\Log\LoggerInterface;

class SyncOrganisationsJob extends TimedJob {
	public function __construct(
		ITimeFactory $time,
		private OrganisationSyncService $sync,
		private LoggerInterface $logger,
	) {
		parent::__construct($time);
		$this->setInterval(24 * 60 * 60);
	}

	protected function run($argument): void {
		try {
			$res = $this->sync->sync();
			$this->logger->info('Org sync finished', ['app' => 'dkmunicipalorganisation'] + $res);
		} catch (\Throwable $e) {
			$this->logger->error('Org sync failed: ' . $e->getMessage(), [
				'app' => 'dkmunicipalorganisation',
				'exception' => $e,
			]);
		}
	}
}
