<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use OCA\GroupFolders\Controller\FolderController;

class CreateFolderCommand extends Command {

	public function __construct(
		private FolderController $folderController,
	) {
		parent::__construct();
	}

	protected function configure(): void {
		$this
			->setName('dkmunicipalorganisation:create-folder')
			->setDescription('Create a team folder');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$output->writeln('<info>Starting folder creation…</info>');

		try {
			$result = $this->folderController->addFolder('Test-51');

			$output->writeln('<info>Folder created successfully.</info>');
			$data = $result->getData();
			$serialized = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
			$output->writeln(sprintf('  %s: %s', 'data', $serialized));

			return Command::SUCCESS;
		} catch (\Throwable $e) {
			$output->writeln('<error>Folder creation failed:</error>');
			$output->writeln('<error>' . $e->getMessage() . '</error>');

			return Command::FAILURE;
		}
	}
}
