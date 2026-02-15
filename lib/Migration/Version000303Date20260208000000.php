<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\IDBConnection;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

class Version000303Date20260208000000 extends SimpleMigrationStep {
	// This migration step is kept for version continuity but does nothing.
	// Default config values are now inserted in Version000303Date20260207000000.
}
