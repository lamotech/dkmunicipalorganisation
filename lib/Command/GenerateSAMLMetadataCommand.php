<?php
declare(strict_types=1);

namespace OCA\DKMunicipalOrganisation\Command;

use OCA\DKMunicipalOrganisation\Service\SAMLService;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class GenerateSAMLMetadataCommand extends Command {

	public function __construct(
		private SAMLService $samlService,
	) {
		parent::__construct();
	}

	protected function configure(): void {
		$this
			->setName('dkmunicipalorganisation:generate-saml-metadata')
			->setDescription('Generate SAML metadata');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$output->writeln('<info>Generating SAML metadata…</info>');

		try {
			$metadata = $this->samlService->createSAMLMetadata();

			$output->writeln('<info>SAML metadata generated successfully.</info>');
			$output->writeln($metadata);

			return Command::SUCCESS;
		} catch (\Throwable $e) {
			$output->writeln('<error>SAML metadata generation failed:</error>');
			$output->writeln('<error>' . $e->getMessage() . '</error>');

			return Command::FAILURE;
		}
	}
}

