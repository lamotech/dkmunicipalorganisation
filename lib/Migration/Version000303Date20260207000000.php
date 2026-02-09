<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\IDBConnection;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

class Version000303Date20260207000000 extends SimpleMigrationStep {
	public function __construct(
		private IDBConnection $db,
	) {}
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

	public function postSchemaChange(IOutput $output, Closure $schemaClosure, array $options): void {
		// Insert default configuration values

		$defaults = [
			'organisation_enable' => '0',
			'cvr' => '11111111',
			'token_issuer_base_url' => 'https://n2adgangsstyring.eksterntest-stoettesystemerne.dk/',
			'token_issuer_endpoint' => '/runtime/api/rest/wstrust/v1/issue',
			'entity_id_organisation' => 'http://stoettesystemerne.dk/service/organisation/3',
			'endpoint_organisation' => 'https://organisation.eksterntest-stoettesystemerne.dk/organisation/organisationsystem/6/',
			'access_control_enable' => '0',
			'idp_metadata_url' => 'https://n2adgangsstyring.eksterntest-stoettesystemerne.dk/runtime/saml2/metadata.idp?samlprofile=nemlogin3',
			'entity_id' => '/index.php/apps/dkmunicipalorganisation/saml/metadata',
			'acs_url' => '/index.php/apps/dkmunicipalorganisation/saml/acs',
			'sls_url' => '/index.php/apps/dkmunicipalorganisation/saml/sls',
		];

		foreach ($defaults as $key => $value) {
			$qb = $this->db->getQueryBuilder();
			$qb->select('configkey')
				->from('dkmunorg_config')
				->where($qb->expr()->eq('configkey', $qb->createNamedParameter($key)));

			$result = $qb->executeQuery();
			$exists = $result->fetch() !== false;
			$result->closeCursor();

			if (!$exists) {
				$qb = $this->db->getQueryBuilder();
				$qb->insert('dkmunorg_config')
					->values([
						'configkey' => $qb->createNamedParameter($key),
						'configvalue' => $qb->createNamedParameter($value),
					])
					->executeStatement();
			}
		}
	}
}
