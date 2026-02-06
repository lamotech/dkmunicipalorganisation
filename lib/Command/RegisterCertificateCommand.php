<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Command;

use OCA\DkMunicipalOrganisation\Db\CertificateRepository;
use OCA\DkMunicipalOrganisation\Enum\CertificateType;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\QuestionHelper;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\Question;

class RegisterCertificateCommand extends Command {
	public function __construct(
		private CertificateRepository $certificateRepository,
	) {
		parent::__construct();
	}

	protected function configure(): void {
		$this
			->setName('dkmunicipalorganisation:register-certificate')
			->setDescription('Register or update the primary PKCS#12 certificate');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		/** @var QuestionHelper $helper */
		$helper = $this->getHelper('question');

		$filepathQuestion = new Question('Enter the certificate filepath: ');
		$filepath = $helper->ask($input, $output, $filepathQuestion);

		if (empty($filepath)) {
			$output->writeln('<error>Filepath cannot be empty</error>');
			return Command::FAILURE;
		}

		if (!file_exists($filepath)) {
			$output->writeln('<error>Certificate file not found: ' . $filepath . '</error>');
			return Command::FAILURE;
		}

		$passwordQuestion = new Question('Enter the certificate password: ');
		$passwordQuestion->setHidden(true);
		$passwordQuestion->setHiddenFallback(false);
		$password = $helper->ask($input, $output, $passwordQuestion);

		$certContent = file_get_contents($filepath);
		if ($certContent === false) {
			$output->writeln('<error>Failed to read certificate file</error>');
			return Command::FAILURE;
		}

		$pkcs12 = [];
		if (!openssl_pkcs12_read($certContent, $pkcs12, $password ?? '')) {
			$output->writeln('<error>Failed to open certificate: ' . openssl_error_string() . '</error>');
			return Command::FAILURE;
		}

		$certResource = openssl_x509_read($pkcs12['cert']);
		if ($certResource === false) {
			$output->writeln('<error>Failed to read X.509 certificate: ' . openssl_error_string() . '</error>');
			return Command::FAILURE;
		}

		$certInfo = openssl_x509_parse($certResource);
		if ($certInfo === false) {
			$output->writeln('<error>Failed to parse X.509 certificate: ' . openssl_error_string() . '</error>');
			return Command::FAILURE;
		}

		$code = CertificateType::Primary->value;
		$existing = $this->certificateRepository->find($code);

		if ($existing !== null) {
			$this->certificateRepository->update($code, $filepath, $password);
			$output->writeln('<info>Certificate updated successfully</info>');
		} else {
			$this->certificateRepository->insert($code, $filepath, $password);
			$output->writeln('<info>Certificate registered successfully</info>');
		}

		$subject = $certInfo['subject']['CN'] ?? $certInfo['name'] ?? 'Unknown';
		$serialNumber = $certInfo['serialNumberHex'] ?? $certInfo['serialNumber'] ?? 'Unknown';
		$expiresAt = (new \DateTimeImmutable())->setTimestamp($certInfo['validTo_time_t']);

		$output->writeln('');
		$output->writeln('<info>Certificate details:</info>');
		$output->writeln('  Subject:       ' . $subject);
		$output->writeln('  Serial Number: ' . $serialNumber);
		$output->writeln('  Expires:       ' . $expiresAt->format('Y-m-d H:i:s'));

		return Command::SUCCESS;
	}
}
