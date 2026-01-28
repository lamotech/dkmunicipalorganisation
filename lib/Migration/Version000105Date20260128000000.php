<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

class Version000105Date20260128000000 extends SimpleMigrationStep {
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('dkmunorg_certificate')) {
			$table = $schema->createTable('dkmunorg_certificate');
			$table->addColumn('code', 'string', ['length' => 100, 'notnull' => true]);
			$table->addColumn('filepath', 'string', ['length' => 256, 'notnull' => true]);
			$table->addColumn('password', 'string', ['length' => 256, 'notnull' => false]);

			$table->setPrimaryKey(['code']);
		}

		return $schema;
	}
}
