<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

class Version000101Date20260102000000 extends SimpleMigrationStep {
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('dkmunorg_org')) {
			$table = $schema->createTable('dkmunorg_org');
			$table->addColumn('org_uuid', 'string', ['length' => 64]);
			$table->addColumn('org_name', 'string', ['length' => 255]);
			$table->addColumn('nc_group_id', 'string', ['length' => 128, 'notnull' => true]);
			$table->addColumn('groupfolder_id', 'integer', ['notnull' => false]);
			$table->addColumn('active', 'boolean', ['default' => true]);
			$table->addColumn('last_seen_at', 'integer', ['notnull' => true, 'default' => 0]);

			$table->setPrimaryKey(['org_uuid']);
			$table->addIndex(['active'], 'dkmunorg_org_active');
		}

		return $schema;
	}
}
