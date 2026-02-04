<?php

declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Controller;

use OCA\DkMunicipalOrganisation\Db\CertificateRepository;
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

	public function saveCertificate(string $filepath, ?string $password): JSONResponse {
		$filepath = trim($filepath);

		if ($filepath === '') {
			return new JSONResponse(['status' => 'error', 'message' => 'Filepath is required'], 400);
		}

		// Save to database
		$existing = $this->certificateRepository->find('Primary');
		if ($existing !== null) {
			$this->certificateRepository->update('Primary', $filepath, $password);
		} else {
			$this->certificateRepository->insert('Primary', $filepath, $password);
		}

		// Validate the certificate
		$validation = $this->validateCertificate($filepath, $password);

		return new JSONResponse([
			'status' => 'ok',
			'validation' => $validation,
		]);
	}

	public function validateCertificate(string $filepath, ?string $password): array {
		$filepath = trim($filepath);

		if ($filepath === '') {
			return ['valid' => false, 'error' => ''];
		}

		if (!file_exists($filepath)) {
			return ['valid' => false, 'error' => 'not_found'];
		}

		$certContent = file_get_contents($filepath);
		if ($certContent === false) {
			return ['valid' => false, 'error' => 'cannot_read'];
		}

		$pkcs12 = [];
		if (!openssl_pkcs12_read($certContent, $pkcs12, $password ?? '')) {
			return ['valid' => false, 'error' => 'cannot_read'];
		}

		$certResource = openssl_x509_read($pkcs12['cert']);
		if ($certResource === false) {
			return ['valid' => false, 'error' => 'cannot_read'];
		}

		$certInfo = openssl_x509_parse($certResource);
		if ($certInfo === false) {
			return ['valid' => false, 'error' => 'cannot_read'];
		}

		$subject = $certInfo['subject']['CN'] ?? $certInfo['name'] ?? '';
		$serialNumber = $certInfo['serialNumberHex'] ?? $certInfo['serialNumber'] ?? '';
		$expiresAt = $certInfo['validTo_time_t'] ?? 0;

		return [
			'valid' => true,
			'subject' => $subject,
			'serialNumber' => $serialNumber,
			'expiresAt' => $expiresAt,
		];
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
