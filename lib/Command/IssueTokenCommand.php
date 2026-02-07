<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Command;

use OCA\DkMunicipalOrganisation\Service\Serviceplatformen\TokenIssuerREST;
use OCA\DkMunicipalOrganisation\Db\CertificateRepository;
use OCA\DkMunicipalOrganisation\Service\Certificate;
use OCA\DkMunicipalOrganisation\Service\Configuration;
use OCA\DkMunicipalOrganisation\Service\TraceLogger;
use OCA\DkMunicipalOrganisation\Enum\CertificateType;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class IssueTokenCommand extends Command {
	public function __construct(
		private CertificateRepository $certificateRepository,
		private Configuration $configuration,
		private TraceLogger $traceLogger,
	) {
		parent::__construct();
	}

	protected function configure(): void {
		$this
			->setName('dkmunicipalorganisation:issue-token')
			->setDescription('Issue a SAML2 token from STS using WS-Trust 1.3');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		//$certificatePassword = (string)$input->getArgument('certificate_password');
		$output->writeln('<info>Issuing SAML token…</info>');

		try {
			$certificate = new Certificate(CertificateType::FKOrganisation, $this->certificateRepository);
			$entityId = $this->configuration->getConfigValue('entity_id_organisation', 'http://stoettesystemerne.dk/service/organisation/3');
			$samlToken = TokenIssuerREST::issueToken(
				$entityId,
				$certificate,
				$this->configuration,
				$this->traceLogger
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

