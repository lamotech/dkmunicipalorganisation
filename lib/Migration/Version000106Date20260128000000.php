<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

class Version000106Date20260128000000 extends SimpleMigrationStep {
	public function __construct(
		private IDBConnection $db,
	) {}

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

	public function postSchemaChange(IOutput $output, Closure $schemaClosure, array $options): void {
		$defaults = [
			'cvr' => '11111111',
			'token_issuer_base_url' => 'https://n2adgangsstyring.eksterntest-stoettesystemerne.dk/',
			'token_issuer_endpoint' => '/runtime/api/rest/wstrust/v1/issue',
			'idp_metadata_url' => 'https://n2adgangsstyring.eksterntest-stoettesystemerne.dk/runtime/saml2/metadata.idp?samlprofile=nemlogin3',
			'entity_id' => '/index.php/apps/dkmunicipalorganisation/saml/metadata',
			'acs_url' => '/index.php/apps/dkmunicipalorganisation/saml/acs',
			'sls_url' => '/index.php/apps/dkmunicipalorganisation/saml/sls',
			'entity_id_organisation' => 'http://stoettesystemerne.dk/service/organisation/3',
			'endpoint_organisation' => 'https://organisation.eksterntest-stoettesystemerne.dk/organisation/organisationsystem/6/',
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
