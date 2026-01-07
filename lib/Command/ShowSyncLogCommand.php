<?php
declare(strict_types=1);

namespace OCA\DKMunicipalOrganisation\Command;

use OCA\DKMunicipalOrganisation\Db\OrgSyncLogRepository;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Helper\Table;

class ShowSyncLogCommand extends Command {

	public function __construct(
		private OrgSyncLogRepository $logRepository,
	) {
		parent::__construct();
	}

	protected function configure(): void {
		$this
			->setName('dkmunicipalorganisation:show-sync-log')
			->setDescription('Display the latest sync log entries')
			->addOption('limit', 'l', InputOption::VALUE_OPTIONAL, 'Number of entries to display', 10);
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$limit = (int)$input->getOption('limit');
		
		try {
			$entries = $this->logRepository->findLatest($limit);

			if (empty($entries)) {
				$output->writeln('<info>No sync log entries found.</info>');
				return Command::SUCCESS;
			}

			$output->writeln(sprintf('<info>Latest %d sync log entries:</info>', count($entries)));
			$output->writeln('');

			$table = new Table($output);
			$table->setHeaders(['Sync Time', 'Received', 'Created', 'Updated', 'Deactivated']);

			foreach ($entries as $entry) {
				$table->addRow([
					$entry['sync_time'] ?? 'N/A',
					(string)($entry['count_received'] ?? 0),
					(string)($entry['created'] ?? 0),
					(string)($entry['updated'] ?? 0),
					(string)($entry['deactivated'] ?? 0),
				]);
			}

			$table->render();

			return Command::SUCCESS;
		} catch (\Throwable $e) {
			$output->writeln('<error>Failed to retrieve sync log:</error>');
			$output->writeln('<error>' . $e->getMessage() . '</error>');

			return Command::FAILURE;
		}
	}
}

