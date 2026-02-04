<?php

declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Dto;

class OrganisationData {
	public function __construct(
		public readonly string $uuid,
		public readonly string $name,
		public readonly string $parentUuid,
	) {
	}
}
