<?php

declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Controller;

use OCA\DkMunicipalOrganisation\Db\CertificateRepository;
use OCA\DkMunicipalOrganisation\Enum\CertificateType;
use OCA\DkMunicipalOrganisation\Service\Certificate;
use OCA\DkMunicipalOrganisation\Service\Configuration;
use OCA\DkMunicipalOrganisation\Service\OrganisationSyncService;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\JSONResponse;
use OCP\IRequest;

class SettingsController extends Controller {

	public function __construct(
		string $appName,
		IRequest $request,
		private CertificateRepository $certificateRepository,
		private Configuration $configuration,
		private OrganisationSyncService $organisationSyncService,
	) {
		parent::__construct($appName, $request);
	}

	/**
	 * Validates the registered primary certificate. Takes no input: the file and
	 * password are read server-side and never sent to or from the browser.
	 * Certificates are registered with occ dkmunicipalorganisation:register-certificate.
	 */
	public function validateCertificate(): JSONResponse {
		try {
			$record = $this->certificateRepository->find(CertificateType::Primary->value);
			if ($record === null) {
				return new JSONResponse(['valid' => false, 'error' => 'not_configured']);
			}
			$certificate = new Certificate(CertificateType::Primary, $this->certificateRepository);
		} catch (\Throwable $e) {
			return new JSONResponse(['valid' => false, 'error' => 'cannot_read']);
		}

		return new JSONResponse([
			'valid' => true,
			'subject' => $certificate->getSubject(),
			'serialNumber' => $certificate->getSerialNumber(),
			'expiresAt' => $certificate->getExpiresAt()->getTimestamp(),
			'legacyStorage' => ($record['storage'] ?? '') !== CertificateRepository::STORAGE_APPDATA,
		]);
	}

	public function saveConfig(string $key, ?string $value): JSONResponse {
		$allowedKeys = ['access_control_enable', 'idp_metadata_url', 'organisation_enable', 'cvr', 'token_issuer_base_url', 'entity_id_organisation', 'endpoint_organisation'];
		if (!in_array($key, $allowedKeys, true)) {
			return new JSONResponse(['status' => 'error', 'message' => 'Invalid config key'], 400);
		}

		$this->configuration->setConfigValue($key, $value);

		return new JSONResponse(['status' => 'ok']);
	}

	public function syncOrganisations(): JSONResponse {
		try {
			$result = $this->organisationSyncService->sync();
			return new JSONResponse($result);
		} catch (\Throwable $e) {
			return new JSONResponse(['status' => 'error', 'message' => $e->getMessage()], 500);
		}
	}
}
