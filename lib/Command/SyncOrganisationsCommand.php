<?php
declare(strict_types=1);

namespace OCA\DKMunicipalOrganisation\Command;

use OCA\DKMunicipalOrganisation\Service\OrganisationSyncService;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class SyncOrganisationsCommand extends Command {

	public function __construct(
		private OrganisationSyncService $syncService,
	) {
		parent::__construct();
	}

	protected function configure(): void {
		$this
			->setName('dkmunicipalorganisation:sync-org')
			->setDescription('Synchronize municipal organisations and team folders');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$output->writeln('<info>Starting organisation synchronization…</info>');

		try {
			$result = $this->syncService->sync();

			$output->writeln('<info>Synchronization finished successfully.</info>');
			foreach ($result as $key => $value) {
				$output->writeln(sprintf('  %s: %s', $key, (string)$value));
			}

			return Command::SUCCESS;
		} catch (\Throwable $e) {
			$output->writeln('<error>Synchronization failed:</error>');
			$output->writeln('<error>' . $e->getMessage() . '</error>');

			return Command::FAILURE;
		}
	}
}
