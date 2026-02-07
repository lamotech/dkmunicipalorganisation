<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Service;

use OCA\DkMunicipalOrganisation\Dto\OrganisationData;
use OCP\Http\Client\IClientService;
use OCP\IConfig;
use OCA\DkMunicipalOrganisation\Service\Serviceplatformen\TokenIssuerREST;
use OCA\DkMunicipalOrganisation\Service\Serviceplatformen\SAMLToken;
use OCA\DkMunicipalOrganisation\Db\CertificateRepository;
use OCA\DkMunicipalOrganisation\Service\Certificate;
use OCA\DkMunicipalOrganisation\Service\Configuration;
use OCA\DkMunicipalOrganisation\Service\TraceLogger;
use OCA\DkMunicipalOrganisation\Enum\CertificateType;
use OCA\DkMunicipalOrganisation\Service\Serviceplatformen\OrganisationConfiguration;
use OCA\DkMunicipalOrganisation\Service\Serviceplatformen\OrganisationWrapper;
use DOMDocument;
use DOMXPath;

class OrgDirectoryClient {
	public function __construct(
		private IClientService $http,
		private IConfig $config,
		private CertificateRepository $certificateRepository,
		private Configuration $configuration,
		private TraceLogger $traceLogger,
	) {}

	/**
	 * @return OrganisationData[]
	 */
	public function fetchOrganisations(): array {
		// Get a SAML Token
		$certificate = new Certificate(CertificateType::FKOrganisation, $this->certificateRepository);
		$entityId = $this->configuration->getConfigValue('entity_id_organisation', 'http://stoettesystemerne.dk/service/organisation/3');
		$samlToken = TokenIssuerREST::issueToken(
			$entityId,
			$certificate,
			$this->configuration,
			$this->traceLogger
		);

		// Setup Organisation Service
		$organisationConfiguration = new OrganisationConfiguration();
		$endpoint = $this->configuration->getConfigValue('endpoint_organisation', 'https://organisation.eksterntest-stoettesystemerne.dk/organisation/organisationsystem/6/');
		$organisationConfiguration->setEndpoint($endpoint);
		$organisationConfiguration->setClientCertificate($certificate);
		$organisationWrapper = new OrganisationWrapper($organisationConfiguration, $samlToken);

		// Get organisations
		$organisations = [];
		$limit = 500;
		$offset = 0;

		while (true) {
			$response = $organisationWrapper->fremsoeg(limit: $limit, offset: $offset);

			$this->traceLogger->trace('organisation_fremsoeg_response', [
				'limit' => $limit,
				'offset' => $offset,
				'responseLength' => strlen($response),
				'response' => substr($response, 0, 2000),
			]);

			// Parse XML and extract EnhedNavn values
			$doc = new DOMDocument();
			$doc->loadXML($response);

			$xpath = new DOMXPath($doc);
			// Register namespaces
			$xpath->registerNamespace('ns2', 'urn:oio:sagdok:3.0.0');
			$xpath->registerNamespace('ns5', 'http://stoettesystemerne.dk/organisation/organisationenhed/6/');
			$xpath->registerNamespace('ns6', 'http://stoettesystemerne.dk/organisation/organisationsystem/6/');

			// Loop through OrganisationEnheder
			$nodes = $xpath->query('//ns6:OrganisationEnheder//ns6:FiltreretOejebliksbillede');

			if (count($nodes) === 0) {
				break;
			}

			foreach ($nodes as $node) {
				$uuid = $xpath->evaluate('string(ns5:ObjektType/ns2:UUIDIdentifikator)', $node);
				$name = $xpath->evaluate('string(ns5:Registrering/ns5:AttributListe/ns5:Egenskab/ns2:EnhedNavn)', $node);
				$parentUuid = $xpath->evaluate('string(ns5:Registrering/ns5:RelationListe/ns2:Overordnet/ns2:ReferenceID/ns2:UUIDIdentifikator)', $node);

				$organisations[] = new OrganisationData($uuid, $name, $parentUuid);
			}

			$offset += $limit;
		}

		return $organisations;
	}
}
