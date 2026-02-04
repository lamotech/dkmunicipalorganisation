<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use DOMDocument;
use DOMXPath;
use OCA\DkMunicipalOrganisation\Service\OrgDirectoryClient;

class FetchOrganisationsCommand extends Command {
	public function __construct(
        private OrgDirectoryClient $orgClient,
	) {
		parent::__construct();
	}

	protected function configure(): void {
		$this
			->setName('dkmunicipalorganisation:fetch-orgs')
			->setDescription('Fetch organisations from the organisation service');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$output->writeln('<info>Fetching organisations…</info>');

		try {
            $orgs = $this->orgClient->fetchOrganisations();

            $output->writeln('<info>Organisation Enheder:</info>');
			foreach ($orgs as $org) {
				$uuid = $org->uuid;
				$name = $org->name;
				$parentUuid = $org->parentUuid;
                
                $output->writeln($uuid . ' - ' . $name . ' - ' . $parentUuid);
			}
            
			return Command::SUCCESS;
		} catch (\Throwable $e) {
			$output->writeln('<error>Organisations fetch failed:</error>');
			$output->writeln('<error>' . $e->getMessage() . '</error>');

			return Command::FAILURE;
		}
	}
}

