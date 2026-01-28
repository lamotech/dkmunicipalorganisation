<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Command;

use OCA\DkMunicipalOrganisation\Service\Serviceplatformen\TokenIssuerREST;
use OCA\DkMunicipalOrganisation\Service\Serviceplatformen\SAMLToken;
use OCA\DkMunicipalOrganisation\Db\CertificateRepository;
use OCA\DkMunicipalOrganisation\Service\Certificate;
use OCA\DkMunicipalOrganisation\Service\Configuration;
use OCA\DkMunicipalOrganisation\Enum\CertificateType;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use OCA\DkMunicipalOrganisation\Service\Serviceplatformen\OrganisationConfiguration;
use OCA\DkMunicipalOrganisation\Service\Serviceplatformen\OrganisationWrapper;
use DOMDocument;
use DOMXPath;

class FetchOrganisationsCommand extends Command {
	public function __construct(
		private CertificateRepository $certificateRepository,
		private Configuration $configuration,
	) {
		parent::__construct();
	}

	protected function configure(): void {
		$this
			->setName('dkmunicipalorganisation:fetch-orgs')
			->setDescription('Fetch organisations from the organisation service');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$output->writeln('<info>Issuing SAML token…</info>');

		try {
			$certificate = new Certificate(CertificateType::FKOrganisation, $this->certificateRepository);
			$entityId = $this->configuration->getConfigValue('entity_id_organisation', 'http://stoettesystemerne.dk/service/organisation/3');
			$samlToken = TokenIssuerREST::issueToken(
				$entityId,
				$certificate,
				$this->configuration
			);
			$output->writeln('<info>Token issued successfully:</info>');

            $output->writeln('<info>Fetching organisations…</info>');

            $organisationConfiguration = new OrganisationConfiguration();
            $endpoint = $this->configuration->getConfigValue('endpoint_organisation', 'https://organisation.eksterntest-stoettesystemerne.dk/organisation/organisationsystem/6/');
            $organisationConfiguration->setEndpoint($endpoint);
            $organisationConfiguration->setClientCertificate($certificate);

            $organisationWrapper = new OrganisationWrapper($organisationConfiguration, $samlToken);
            $response = $organisationWrapper->fremsoeg(limit: 5, offset: 0);
            $output->writeln('<info>Organisations fetched successfully</info>');
            
            // Parse XML and extract EnhedNavn values
            $doc = new DOMDocument();
            $doc->loadXML($response);
            
            $xpath = new DOMXPath($doc);
            // Register namespaces
            $xpath->registerNamespace('ns2', 'urn:oio:sagdok:3.0.0');
            $xpath->registerNamespace('ns5', 'http://stoettesystemerne.dk/organisation/organisationenhed/6/');
            $xpath->registerNamespace('ns6', 'http://stoettesystemerne.dk/organisation/organisationsystem/6/');
            
            // Find all EnhedNavn nodes
            $enhedNavnNodes = $xpath->query('//ns6:OrganisationEnheder//ns5:Egenskab//ns2:EnhedNavn');
            
            $output->writeln('<info>Organisation Units (EnhedNavn):</info>');
            if ($enhedNavnNodes->length > 0) {
                foreach ($enhedNavnNodes as $node) {
                    $value = trim($node->nodeValue);
                    if ($value !== '') {
                        $output->writeln('  - ' . $value);
                    }
                }
            } else {
                $output->writeln('  (No organisation units found)');
            }

			return Command::SUCCESS;
		} catch (\Throwable $e) {
			$output->writeln('<error>Organisations fetch failed:</error>');
			$output->writeln('<error>' . $e->getMessage() . '</error>');

			return Command::FAILURE;
		}
	}
}

