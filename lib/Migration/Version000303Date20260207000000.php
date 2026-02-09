<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

class Version000303Date20260207000000 extends SimpleMigrationStep {
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('dkmunorg_org')) {
			$table = $schema->createTable('dkmunorg_org');
			$table->addColumn('org_uuid', 'string', ['length' => 64]);
			$table->addColumn('org_name', 'string', ['length' => 255]);
			$table->addColumn('nc_group_id', 'string', ['length' => 128, 'notnull' => true]);
			$table->addColumn('groupfolder_id', 'integer', ['notnull' => false]);
			$table->addColumn('active', 'boolean', ['notnull' => false, 'default' => true]);
			$table->addColumn('last_seen_at', 'integer', ['notnull' => true, 'default' => 0]);
			$table->addColumn('org_parent_uuid', 'string', ['length' => 64]);

			$table->setPrimaryKey(['org_uuid']);
			$table->addIndex(['active'], 'dkmunorg_org_active');
		}

		if (!$schema->hasTable('dkmunorg_org_log')) {
			$table = $schema->createTable('dkmunorg_org_log');
			$table->addColumn('sync_time', 'datetime', ['notnull' => true]);
			$table->addColumn('count_received', 'integer', ['notnull' => true]);
			$table->addColumn('created', 'integer', ['notnull' => true]);
			$table->addColumn('updated', 'integer', ['notnull' => true]);
			$table->addColumn('deactivated', 'integer', ['notnull' => true]);
		}		

		if (!$schema->hasTable('dkmunorg_certificate')) {
			$table = $schema->createTable('dkmunorg_certificate');
			$table->addColumn('code', 'string', ['length' => 100, 'notnull' => true]);
			$table->addColumn('filepath', 'string', ['length' => 256, 'notnull' => true]);
			$table->addColumn('password', 'string', ['length' => 256, 'notnull' => false]);

			$table->setPrimaryKey(['code']);
		}

		if (!$schema->hasTable('dkmunorg_config')) {
			$table = $schema->createTable('dkmunorg_config');
			$table->addColumn('configkey', 'string', ['length' => 100, 'notnull' => true]);
			$table->addColumn('configvalue', 'text', ['notnull' => false]);

			$table->setPrimaryKey(['configkey']);
		}		
		return $schema;
	}
}
