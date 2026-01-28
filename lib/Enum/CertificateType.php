<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Enum;

enum CertificateType: string {
	case Primary = 'Primary';
	case FKAccess = 'FKAccess';
	case FKOrganisation = 'FKOrganisation';
}
