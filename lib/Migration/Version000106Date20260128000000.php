<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

class Version000106Date20260128000000 extends SimpleMigrationStep {
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('dkmunorg_config')) {
			$table = $schema->createTable('dkmunorg_config');
			$table->addColumn('configkey', 'string', ['length' => 100, 'notnull' => true]);
			$table->addColumn('configvalue', 'text', ['notnull' => false]);

			$table->setPrimaryKey(['configkey']);
		}

		return $schema;
	}
}
