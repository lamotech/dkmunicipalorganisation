<?php

namespace OCA\DkMunicipalOrganisation\BackgroundJob;

use OCP\BackgroundJob\TimedJob;
use OCP\AppFramework\Utility\ITimeFactory;
use OCA\DkMunicipalOrganisation\Service\Configuration;
use OCA\DkMunicipalOrganisation\Service\OrganisationSyncService;
use Psr\Log\LoggerInterface;

class SyncOrganisationsJob extends TimedJob {
	private const TARGET_HOUR = 0; // Run at midnight (00:00-00:59)

	public function __construct(
		ITimeFactory $time,
		private OrganisationSyncService $organisationSyncService,
		private Configuration $configuration,
		private LoggerInterface $logger,
	) {
		parent::__construct($time);
		$this->setInterval(60 * 60); // Check every hour
	}

	protected function run($argument): void {
		$now = $this->time->getDateTime();
		$currentHour = (int)$now->format('G');
		$today = $now->format('Y-m-d');

		// Only run during the target hour (midnight)
		if ($currentHour !== self::TARGET_HOUR && $currentHour !== self::TARGET_HOUR+1) {
			return;
		}

		// Check if we already ran today
		$lastRunDate = $this->configuration->getConfigValue('organisation_last_sync_date', '');
		if ($lastRunDate === $today) {
			return;
		}

		if ($this->configuration->getConfigValue('organisation_enable', '0') !== '1') {
			$this->logger->debug('Org sync skipped: organisation not enabled', ['app' => 'dkmunicipalorganisation']);
			return;
		}

		try {
			$res = $this->organisationSyncService->sync();
			$this->configuration->setConfigValue('organisation_last_sync_date', $today);
			$this->logger->info('Org sync finished', ['app' => 'dkmunicipalorganisation'] + $res);
		} catch (\Throwable $e) {
			$this->logger->error('Org sync failed: ' . $e->getMessage(), [
				'app' => 'dkmunicipalorganisation',
				'exception' => $e,
			]);
		}
	}
}
