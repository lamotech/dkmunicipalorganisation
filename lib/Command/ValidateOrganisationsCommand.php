<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Command;

use OCA\DkMunicipalOrganisation\Db\OrganisationRepository;
use OCA\GroupFolders\Folder\FolderManager;
use OCP\Constants;
use OCP\IGroupManager;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Helper\Table;

class ValidateOrganisationsCommand extends Command {
	private const REQUIRED_PERMISSIONS = Constants::PERMISSION_READ 
		| Constants::PERMISSION_UPDATE 
		| Constants::PERMISSION_CREATE 
		| Constants::PERMISSION_SHARE 
		| Constants::PERMISSION_DELETE;

	public function __construct(
		private OrganisationRepository $orgRepository,
		private FolderManager $folderManager,
		private IGroupManager $groupManager,
	) {
		parent::__construct();
	}

	protected function configure(): void {
		$this
			->setName('dkmunicipalorganisation:validate-org')
			->setDescription('Validate active organisations and folders');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$output->writeln('<info>Starting organisation validation…</info>');
		$output->writeln('');

		try {
			$organisations = $this->orgRepository->findAllActive();
			$issues = [];

			// Build a map of existing UUIDs for quick lookup
			$existingUuids = [];
			foreach ($organisations as $org) {
				$existingUuids[$org['org_uuid']] = true;
			}

			// Cache folders to avoid multiple calls
			$foldersCache = null;
			$foldersById = [];

			foreach ($organisations as $org) {
				$uuid = $org['org_uuid'];
				$name = $org['org_name'];
				$parentUuid = $org['org_parent_uuid'] ?? null;
				$groupId = $org['nc_group_id'];
				$folderId = $org['groupfolder_id'] ?? null;

				// 1. Check if parent UUID exists
				if ($parentUuid !== null && $parentUuid !== '' && !isset($existingUuids[$parentUuid])) {
					$issues[] = [
						'type' => 'Missing Parent',
						'uuid' => $uuid,
						'name' => $name,
						'message' => "Parent UUID '{$parentUuid}' does not exist",
					];
				}

				// 2. Validate folder exists and name matches
				$folder = null;
				if ($folderId !== null) {
					try {
						// Load folders cache on first use
						if ($foldersCache === null) {
							$foldersCache = $this->folderManager->getAllFolders();
							// Build index by ID for quick lookup
							foreach ($foldersCache as $folderObj) {
								$fid = (int)$folderObj->id;
								if ($fid > 0) {
									$foldersById[$fid] = $folderObj;
								}
							}
						}

						$folder = $foldersById[(int)$folderId] ?? null;

						if ($folder === null) {
							$issues[] = [
								'type' => 'Folder Missing',
								'uuid' => $uuid,
								'name' => $name,
								'message' => "Group folder with ID {$folderId} does not exist",
							];
						} else {
							$folderName = $folder->mountPoint;
							if ($folderName !== $name) {
								$issues[] = [
									'type' => 'Folder Name Mismatch',
									'uuid' => $uuid,
									'name' => $name,
									'message' => "Folder name '{$folderName}' does not match organisation name '{$name}'",
								];
							}
						}
					} catch (\Throwable $e) {
						$issues[] = [
							'type' => 'Folder Error',
							'uuid' => $uuid,
							'name' => $name,
							'message' => "Error checking folder: " . $e->getMessage(),
						];
					}
				} else {
					$issues[] = [
						'type' => 'No Folder ID',
						'uuid' => $uuid,
						'name' => $name,
						'message' => "Organisation has no groupfolder_id",
					];
				}

				// 3. Validate group exists
				$group = $this->groupManager->get($groupId);
				if ($group === null) {
					$issues[] = [
						'type' => 'Group Missing',
						'uuid' => $uuid,
						'name' => $name,
						'message' => "Group '{$groupId}' does not exist",
					];
				}

				// 4. Validate group permissions on folder
				if ($folderId !== null && $group !== null && $folder !== null) {
					try {
						$groups = $folder->groups ?? [];
						$groupPermissions = null;
						
						// Find the group in the folder's groups
						// Handle both array formats: ['groupid' => permissions] or ['groupid' => ['permissions' => ...]]
						foreach ($groups as $gid => $perms) {
							if ($gid === $groupId) {
								$groupPermissions = is_int($perms) ? $perms : (int)($perms['permissions'] ?? 0);
								break;
							}
						}

						if ($groupPermissions === null) {
							$issues[] = [
								'type' => 'Group Not in Folder',
								'uuid' => $uuid,
								'name' => $name,
								'message' => "Group '{$groupId}' is not assigned to folder {$folderId}",
							];
						} elseif (($groupPermissions & self::REQUIRED_PERMISSIONS) !== self::REQUIRED_PERMISSIONS) {
							$issues[] = [
								'type' => 'Insufficient Permissions',
								'uuid' => $uuid,
								'name' => $name,
								'message' => "Group '{$groupId}' does not have required permissions on folder {$folderId} (has: {$groupPermissions}, required: " . self::REQUIRED_PERMISSIONS . ")",
							];
						}
					} catch (\Throwable $e) {
						$issues[] = [
							'type' => 'Permission Check Error',
							'uuid' => $uuid,
							'name' => $name,
							'message' => "Error checking permissions: " . $e->getMessage(),
						];
					}
				}
			}

			if (empty($issues)) {
				$output->writeln('<info>✓ All validations passed. No issues found.</info>');
				return Command::SUCCESS;
			}

			$output->writeln(sprintf('<error>Found %d issue(s):</error>', count($issues)));
			$output->writeln('');

			$table = new Table($output);
			$table->setHeaders(['Type', 'UUID', 'Name', 'Issue']);

			foreach ($issues as $issue) {
				$table->addRow([
					$issue['type'],
					$issue['uuid'],
					$issue['name'],
					$issue['message'],
				]);
			}

			$table->render();

			return Command::FAILURE;
		} catch (\Throwable $e) {
			$output->writeln('<error>Validation failed:</error>');
			$output->writeln('<error>' . $e->getMessage() . '</error>');
			$output->writeln('<error>' . $e->getTraceAsString() . '</error>');

			return Command::FAILURE;
		}
	}
}

