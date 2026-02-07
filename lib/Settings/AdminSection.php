<?php

declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Settings;

use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\Settings\IIconSection;

class AdminSection implements IIconSection {

	public function __construct(
		private IURLGenerator $url,
		private IL10N $l,
	) {
	}

	public function getID(): string {
		return 'dkmunicipalorganisation';
	}

	public function getName(): string {
		return $this->l->t('DK Municipal Access');
	}

	public function getPriority(): int {
		return 75;
	}

	public function getIcon(): string {
		return $this->url->imagePath('dkmunicipalorganisation', 'app-dark.svg');
	}
}
