<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use OCA\GroupFolders\Folder\FolderManager;

class RenameFolderCommand extends Command {

	public function __construct(
		private FolderManager $folderManager,
	) {
		parent::__construct();
	}

	protected function configure(): void {
		$this
			->setName('dkmunicipalorganisation:rename-folder')
			->setDescription('Rename a team folder')
			->addArgument('folder_id', InputArgument::REQUIRED, 'Id of the folder to rename')
			->addArgument('name', InputArgument::REQUIRED, 'New value name of the folder');            
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$folderId = (int)$input->getArgument('folder_id');
		$newName = trim((string)$input->getArgument('name'));
		$output->writeln('<info>Starting folder renaming…</info>');

		try {
			$this->folderManager->renameFolder($folderId, $newName);

			$output->writeln('<info>Folder renamed successfully.</info>');
			
			return Command::SUCCESS;
		} catch (\Throwable $e) {
			$output->writeln('<error>Folder renaming failed:</error>');
			$output->writeln('<error>' . $e->getMessage() . '</error>');

			return Command::FAILURE;
		}
	}
}
