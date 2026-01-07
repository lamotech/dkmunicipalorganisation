<?php
declare(strict_types=1);

namespace OCA\DKMunicipalOrganisation\Service;

use OCP\Http\Client\IClientService;
use OCP\IConfig;

class OrgDirectoryClient {
	public function __construct(
		private IClientService $http,
		private IConfig $config,
	) {}

	/**
	 * @return array<int, array{uuid:string, name:string}>
	 */
	public function fetchOrganisations(): array {
        /*
		$url = (string)$this->config->getAppValue('dkmunicipalorganisation', 'org_service_url', '');
		if ($url === '') {
			throw new \RuntimeException('org_service_url is not configured');
		}

		$client = $this->http->newClient();
		$res = $client->get($url, [
			'timeout' => 20,
			'headers' => [
				'Accept' => 'application/json',
			],
		]);

		$data = json_decode($res->getBody(), true, 512, JSON_THROW_ON_ERROR);

		// Normalize: expect array of items with uuid + name
		$out = [];
		foreach ($data as $item) {
			if (!isset($item['uuid'], $item['name'])) {
				continue;
			}
			$out[] = ['uuid' => (string)$item['uuid'], 'name' => (string)$item['name']];
		}*/

        $out = [
            ['uuid' => 'ada1f8a7-31d0-4fc8-9866-8e3182f40ef2', 'name' => 'Root Organisation', 'parentuuid' => null],
            ['uuid' => '29de658d-8ae0-4881-a040-6fd37aaddf26', 'name' => 'Test Organisation 1', 'parentuuid' => 'ada1f8a7-31d0-4fc8-9866-8e3182f40ef2'],
            ['uuid' => '6215fe52-6060-4575-b0f7-b439740832a6', 'name' => 'Test Organisation 2', 'parentuuid' => 'ada1f8a7-31d0-4fc8-9866-8e3182f40ef2'],
            ['uuid' => '04b77640-0761-4e6f-9810-aad455d929f9', 'name' => 'Test Organisation 2-1', 'parentuuid' => '6215fe52-6060-4575-b0f7-b439740832a6'],
            ['uuid' => '4315e237-3f23-495d-9dcd-72d85f9911de', 'name' => 'Test Organisation 2-2', 'parentuuid' => '6215fe52-6060-4575-b0f7-b439740832a6'],
            ['uuid' => '7cfb9ecd-b537-43ab-b2c9-fc9739e5b93f', 'name' => 'Test Organisation 3', 'parentuuid' => 'ada1f8a7-31d0-4fc8-9866-8e3182f40ef2'],
        ];
		return $out;
	}
}
