<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use OCA\GroupFolders\Folder\FolderManager;
use OCP\Constants;

class SetFolderPermissionsCommand extends Command {
	public const PERMISSION_VALUES = [
		'read' => Constants::PERMISSION_READ,
		'write' => Constants::PERMISSION_UPDATE | Constants::PERMISSION_CREATE,
		'share' => Constants::PERMISSION_SHARE,
		'delete' => Constants::PERMISSION_DELETE,
	];

	public function __construct(
		private FolderManager $folderManager,
	) {
		parent::__construct();
	}

	protected function configure(): void {
		$this
			->setName('dkmunicipalorganisation:set-folder-permissions')
			->setDescription('Set folder permissions')
			->addArgument('folder_id', InputArgument::REQUIRED, 'Id of the folder to set permissions for')
			->addArgument('permissions', InputArgument::OPTIONAL | InputArgument::IS_ARRAY, 'The permissions to set for the group as a white space separated list (ex: read write). Leave empty for read only');            
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$output->writeln('<info>Starting folder permissions setting…</info>');

        $folderId = (int)$input->getArgument('folder_id');
		$groupString = "org_4315e237-3f23-495d-9dcd-72d85f9911de";
		$permissionsString = ["read", "write"];
		$permissions = $this->getNewPermissions($permissionsString);

		try {
			$this->folderManager->addApplicableGroup($folderId, $groupString);
            $this->folderManager->setGroupPermissions($folderId, $groupString, $permissions);

			$output->writeln('<info>Folder permissions set successfully.</info>');
			
			return Command::SUCCESS;
		} catch (\Throwable $e) {
			$output->writeln('<error>Folder permissions setting failed:</error>');
			$output->writeln('<error>' . $e->getMessage() . '</error>');

			return Command::FAILURE;
		}
	}

	private function getNewPermissions(array $input): int {
		$permissions = 1;
		$values = self::PERMISSION_VALUES;
		foreach ($input as $permissionsString) {
			if (isset($values[$permissionsString])) {
				$permissions |= self::PERMISSION_VALUES[$permissionsString];
			} else {
				return 0;
			}
		}

		return $permissions;
	}	
}
