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

class IssueTokenCommand extends Command {

	protected function configure(): void {
		$this
			->setName('dkmunicipalorganisation:issue-token')
			->setDescription('Issue a SAML2 token from STS using WS-Trust 1.3');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$output->writeln('<info>Issuing SAML token…</info>');

		try {
			$certificatesPath = '/var/www/html/apps-extra/dkmunicipalorganisation/certificates/';
			$samlToken = TokenIssuerREST::issueToken(
				entityId: "http://stoettesystemerne.dk/service/organisation/3",
				clientCertificatePath: $certificatesPath . 'Serviceplatformen.p12',
				clientCertificatePassword: '********',
				cvr: "11111111",
				tokenIssuerBaseUrl: "https://n2adgangsstyring.eksterntest-stoettesystemerne.dk/"
			);
			$output->writeln('<info>Token issued successfully:</info>');
			$output->writeln(json_encode($samlToken->getMetadata(), JSON_PRETTY_PRINT));

			$output->writeln('<info>Token assertion:</info>');
			$output->writeln($samlToken->getAssertion());

			return Command::SUCCESS;
		} catch (\Throwable $e) {
			$output->writeln('<error>Token issuance failed:</error>');
			$output->writeln('<error>' . $e->getMessage() . '</error>');

			return Command::FAILURE;
		}
	}
}

