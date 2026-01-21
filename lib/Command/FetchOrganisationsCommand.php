<?php
declare(strict_types=1);

namespace OCA\DKMunicipalOrganisation\Command;

use OCA\DKMunicipalOrganisation\Service\Serviceplatformen\TokenIssuer;
use OCA\DKMunicipalOrganisation\Service\Serviceplatformen\TokenIssuerREST;
use OCA\DKMunicipalOrganisation\Service\Serviceplatformen\SAMLToken;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use OCA\DKMunicipalOrganisation\Service\Serviceplatformen\OrganisationConfiguration;
use OCA\DKMunicipalOrganisation\Service\Serviceplatformen\OrganisationWrapper;
use DOMDocument;
use DOMXPath;

class FetchOrganisationsCommand extends Command {

	protected function configure(): void {
		$this
			->setName('dkmunicipalorganisation:fetch-orgs')
			->setDescription('Fetch organisations from the organisation service')
            ->addArgument('certificate_password', InputArgument::REQUIRED, 'Password for the certificate');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$certificatePassword = (string)$input->getArgument('certificate_password');
		$output->writeln('<info>Issuing SAML token…</info>');

		try {
			$certificatesPath = '/var/www/html/apps-extra/dkmunicipalorganisation/certificates/';
			$samlToken = TokenIssuerREST::issueToken(
				entityId: "http://stoettesystemerne.dk/service/organisation/3",
				clientCertificatePath: $certificatesPath . 'Serviceplatformen.p12',
				clientCertificatePassword: $certificatePassword,
				cvr: "11111111",
				tokenIssuerBaseUrl: "https://n2adgangsstyring.eksterntest-stoettesystemerne.dk/"
			);
			$output->writeln('<info>Token issued successfully:</info>');

            $output->writeln('<info>Fetching organisations…</info>');

            $organisationConfiguration = new OrganisationConfiguration();
            $organisationConfiguration->setEndpoint("https://organisation.eksterntest-stoettesystemerne.dk/organisation/organisationsystem/6/");
            $organisationConfiguration->setClientCertificatePath($certificatesPath . 'Serviceplatformen.p12');
            $organisationConfiguration->setClientCertificatePassword($certificatePassword);
            //$organisationConfiguration->setOrganisationServiceCertificatePath($certificatesPath . 'current_ORG_EXTTEST_Organisation_1.cer');

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

