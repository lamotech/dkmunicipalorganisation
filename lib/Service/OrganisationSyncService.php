<?php

// lib/Service/OrganisationSyncService.php
namespace OCA\DkMunicipalOrganisation\Service;

use OCA\DkMunicipalOrganisation\Db\OrganisationRepository;
use OCA\DkMunicipalOrganisation\Dto\OrganisationData;
use OCA\DkMunicipalOrganisation\Db\OrgSyncLogRepository;
use OCA\DkMunicipalOrganisation\Service\OrgDirectoryClient;
use OCP\IGroupManager;
use OCP\AppFramework\Utility\ITimeFactory;
use OCA\GroupFolders\Folder\FolderManager;
use OCP\Constants;

class OrganisationSyncService {
	public function __construct(
		private OrgDirectoryClient $orgClient,
		private OrganisationRepository $repo,
		private IGroupManager $groups,
		private ITimeFactory $time,
		private FolderManager $folderManager,
		private OrgSyncLogRepository $orgSyncLogRepository,
	) {}

	public function sync(): array {
		$orgs = $this->orgClient->fetchOrganisations();
		$seen = [];
		$created = 0; $updated = 0; $deactivated = 0;

		// Optional: cache existing TF folders to avoid N API calls
		// $existingFolders = $this->teamFolders->listFolders();

		if(count($orgs) > 0) {
			foreach ($orgs as $org) {
				$uuid = $org->uuid;
				$name = $org->name;
				$parentUuid = $org->parentUuid;
				$seen[$uuid] = true;

				$row = $this->repo->find($uuid);
				if ($row === null) {
					$folderId = $this->createOrganisation($uuid, $name, $parentUuid);
					$created++;
				} else {
					$folderId = (int)$row['groupfolder_id'];
					if ($row['org_name'] !== $name || $row['org_parent_uuid'] !== $parentUuid) {
						$this->updateOrganisation($uuid, $name, $folderId, $parentUuid);
						$updated++;
					}
					$this->repo->touch($uuid, $this->time->getTime());
					if (!(bool)$row['active']) {
						$this->repo->setActive($uuid, true);
					}
				}
			}

			// Deactivate missing orgs
			$missing = $this->repo->findActiveNotIn(array_keys($seen));
			foreach ($missing as $row) {
				$this->repo->setActive($row['org_uuid'], false);
				$deactivated++;
				// Optional: revoke group access / set permissions to none (policy decision)
			}
		}

		$this->orgSyncLogRepository->insert($this->time->getDateTime(), count($orgs), $created, $updated, $deactivated);

		return [
			'fetched' => count($orgs),
			'created' => $created,
			'updated' => $updated,
			'deactivated' => $deactivated,
		];
	}

	public function createOrganisation(string $uuid, string $name, string $parentUuid): int {
		$groupId = 'org_' . strtolower($uuid);
		if ($this->groups->get($groupId) === null) {
			$this->groups->createGroup($groupId);
		}		
		$permissions = Constants::PERMISSION_READ | Constants::PERMISSION_UPDATE | Constants::PERMISSION_CREATE | Constants::PERMISSION_SHARE | Constants::PERMISSION_DELETE;

		$folderId = $this->folderManager->createFolder($name);

		$this->folderManager->addApplicableGroup($folderId, $groupId);
		$this->folderManager->setGroupPermissions($folderId, $groupId, $permissions);

		$this->repo->insert($uuid, $name, $groupId, $folderId, $parentUuid);
		
		return $folderId;
	}

	public function updateOrganisation(string $uuid, string $name, int $folderId, string $parentUuid): void {
		$this->folderManager->renameFolder($folderId, $name);
		$this->repo->updateOrganisation($uuid, $name, $parentUuid);
	}
}
