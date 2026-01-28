<?php
declare(strict_types=1);

namespace OCA\DkMunicipalOrganisation\Service;

use OCP\IDBConnection;

class Configuration {
	private array $cache = [];

	public function __construct(
		private IDBConnection $db,
	) {}

	public function getConfigValue(string $key, ?string $default = null): ?string {
		if (isset($this->cache[$key])) {
			return $this->cache[$key];
		}

		$qb = $this->db->getQueryBuilder();
		$qb->select('configvalue')
			->from('dkmunorg_config')
			->where($qb->expr()->eq('configkey', $qb->createNamedParameter($key)));

		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();

		if ($row === false) {
			return $default;
		}

		$this->cache[$key] = $row['configvalue'];
		return $row['configvalue'];
	}

	public function setConfigValue(string $key, ?string $value): void {
		$existing = $this->getConfigValue($key);

		$qb = $this->db->getQueryBuilder();

		if ($existing !== null || $this->configKeyExists($key)) {
			$qb->update('dkmunorg_config')
				->set('configvalue', $qb->createNamedParameter($value))
				->where($qb->expr()->eq('configkey', $qb->createNamedParameter($key)))
				->executeStatement();
		} else {
			$qb->insert('dkmunorg_config')
				->values([
					'configkey' => $qb->createNamedParameter($key),
					'configvalue' => $qb->createNamedParameter($value),
				])
				->executeStatement();
		}

		$this->cache[$key] = $value;
	}

	public function deleteConfigValue(string $key): void {
		$qb = $this->db->getQueryBuilder();
		$qb->delete('dkmunorg_config')
			->where($qb->expr()->eq('configkey', $qb->createNamedParameter($key)))
			->executeStatement();

		unset($this->cache[$key]);
	}

	public function getAllConfigValues(): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('configkey', 'configvalue')
			->from('dkmunorg_config');

		$result = $qb->executeQuery();
		$configs = [];

		while ($row = $result->fetch()) {
			$configs[$row['configkey']] = $row['configvalue'];
			$this->cache[$row['configkey']] = $row['configvalue'];
		}

		$result->closeCursor();
		return $configs;
	}

	private function configKeyExists(string $key): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->select('configkey')
			->from('dkmunorg_config')
			->where($qb->expr()->eq('configkey', $qb->createNamedParameter($key)));

		$result = $qb->executeQuery();
		$exists = $result->fetch() !== false;
		$result->closeCursor();

		return $exists;
	}
}
