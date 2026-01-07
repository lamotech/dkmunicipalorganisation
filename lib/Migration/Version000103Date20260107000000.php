<?php
declare(strict_types=1);

namespace OCA\DKMunicipalOrganisation\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

class Version000103Date20260107000000 extends SimpleMigrationStep {
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if ($schema->hasTable('dkmunorg_org')) {
			$table = $schema->getTable('dkmunorg_org');
			if (!$table->hasColumn('org_parent_uuid')) {
				$table->addColumn('org_parent_uuid', 'string', ['length' => 64]);
			}
		}

		if (!$schema->hasTable('dkmunorg_org_log')) {
			$table = $schema->createTable('dkmunorg_org_log');
			$table->addColumn('sync_time', 'datetime', ['notnull' => true]);
			$table->addColumn('count_received', 'integer', ['notnull' => true]);
			$table->addColumn('created', 'integer', ['notnull' => true]);
			$table->addColumn('updated', 'integer', ['notnull' => true]);
			$table->addColumn('deactivated', 'integer', ['notnull' => true]);
		}

		return $schema;
	}
}

