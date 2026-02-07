<template>
	<div class="dkmunorg-admin-settings">
		<NcSettingsSection :name="t('dkmunicipalorganisation', 'Prerequisites')">
			<div class="dkmunorg-prerequisite">
				<div v-if="groupfoldersEnabled" class="dkmunorg-cert-info-box">
					<div><span class="dkmunorg-check">&#10004;</span><strong>{{ t('dkmunicipalorganisation', 'Group folders is installed') }}</strong></div>
				</div>
				<div v-else class="certificate-error">
					<div><strong>{{ t('dkmunicipalorganisation', 'Group folders is not installed - the app is required') }}</strong></div>
				</div>
			</div>
		</NcSettingsSection>

		<NcSettingsSection :name="t('dkmunicipalorganisation', 'System certificate')">
			<p>{{ t('dkmunicipalorganisation', 'Copy your system certificate to the server and run this command in the root of the Nextcloud installation to register it:') }}</p>
			<br/>
			<p><strong>php occ dkmunicipalorganisation:register-certificate</strong></p>
			<br/>

			<div v-if="certError === 'not_found'" class="certificate-error">
				{{ t('dkmunicipalorganisation', 'The certificate was not found at the specified path') }}
			</div>
			<div v-else-if="certError === 'cannot_read'" class="certificate-error">
				{{ t('dkmunicipalorganisation', 'The certificate cannot be read') }}
			</div>
			<div v-else-if="certSubject" class="dkmunorg-cert-info-box">
				<div><strong>{{ t('dkmunicipalorganisation', 'Name:') }}</strong> {{ certSubject }}</div>
				<div><strong>{{ t('dkmunicipalorganisation', 'Serial number:') }}</strong> {{ certSerialNumber }}</div>
				<div><strong>{{ t('dkmunicipalorganisation', 'Expires:') }}</strong> {{ certExpiresFormatted }}</div>
			</div>
		</NcSettingsSection>

		<NcSettingsSection :name="t('dkmunicipalorganisation', 'Organisation')">
			<p>{{ t('dkmunicipalorganisation', 'Settings for organisation integration.') }}</p>

			<NcCheckboxRadioSwitch id="org-enable"
				v-model="organisationEnable"
				type="switch">
				{{ t('dkmunicipalorganisation', 'Enable') }}
			</NcCheckboxRadioSwitch>

			<table class="dkmunorg-cert-table">
				<tr>
					<td class="dkmunorg-cert-label">
						<label for="org-cvr">{{ t('dkmunicipalorganisation', 'CVR number') }}</label>
					</td>
					<td>
						<input id="org-cvr"
							v-model="cvr"
							type="text"
							:style="{ width: '200px', maxWidth: '100%', boxSizing: 'border-box' }"
							@change="saveConfigValue('cvr', cvr)">
					</td>
				</tr>
				<tr>
					<td class="dkmunorg-cert-label">
						<label for="org-token-url">{{ t('dkmunicipalorganisation', 'Token service URL') }}</label>
					</td>
					<td>
						<input id="org-token-url"
							v-model="tokenIssuerBaseUrl"
							type="text"
							:style="{ width: '600px', maxWidth: '100%', boxSizing: 'border-box' }"
							@change="saveConfigValue('token_issuer_base_url', tokenIssuerBaseUrl)">
					</td>
				</tr>
				<tr>
					<td class="dkmunorg-cert-label">
						<label for="org-entity-id">{{ t('dkmunicipalorganisation', 'Entity ID for organisation') }}</label>
					</td>
					<td>
						<input id="org-entity-id"
							v-model="entityIdOrganisation"
							type="text"
							:style="{ width: '600px', maxWidth: '100%', boxSizing: 'border-box' }"
							@change="saveConfigValue('entity_id_organisation', entityIdOrganisation)">
					</td>
				</tr>
				<tr>
					<td class="dkmunorg-cert-label">
						<label for="org-endpoint">{{ t('dkmunicipalorganisation', 'Endpoint for organisation service') }}</label>
					</td>
					<td>
						<input id="org-endpoint"
							v-model="endpointOrganisation"
							type="text"
							:style="{ width: '600px', maxWidth: '100%', boxSizing: 'border-box' }"
							@change="saveConfigValue('endpoint_organisation', endpointOrganisation)">
					</td>
				</tr>
			</table>

			<div class="dkmunorg-button-row">
				<button class="primary" :disabled="syncing" @click="syncOrganisations">
					{{ syncing ? t('dkmunicipalorganisation', 'Synchronizing...') : t('dkmunicipalorganisation', 'Synchronize organisations now') }}
				</button>
			</div>

			<div v-if="syncResult" class="dkmunorg-cert-info-box">
				<div><strong>{{ t('dkmunicipalorganisation', 'Fetched:') }}</strong> {{ syncResult.fetched }}</div>
				<div><strong>{{ t('dkmunicipalorganisation', 'Created:') }}</strong> {{ syncResult.created }}</div>
				<div><strong>{{ t('dkmunicipalorganisation', 'Updated:') }}</strong> {{ syncResult.updated }}</div>
				<div><strong>{{ t('dkmunicipalorganisation', 'Deactivated:') }}</strong> {{ syncResult.deactivated }}</div>
			</div>
			<div v-if="syncError" class="certificate-error">
				{{ syncError }}
			</div>

			<table v-if="syncLog.length > 0" class="dkmunorg-sync-log-table">
				<caption>{{ t('dkmunicipalorganisation', 'Synchronization log') }}</caption>
				<thead>
					<tr>
						<th>{{ t('dkmunicipalorganisation', 'Time') }}</th>
						<th>{{ t('dkmunicipalorganisation', 'Fetched') }}</th>
						<th>{{ t('dkmunicipalorganisation', 'Created') }}</th>
						<th>{{ t('dkmunicipalorganisation', 'Updated') }}</th>
						<th>{{ t('dkmunicipalorganisation', 'Deactivated') }}</th>
					</tr>
				</thead>
				<tbody>
					<tr v-for="(entry, index) in syncLog" :key="index">
						<td>{{ entry.sync_time }}</td>
						<td>{{ entry.count_received }}</td>
						<td>{{ entry.created }}</td>
						<td>{{ entry.updated }}</td>
						<td>{{ entry.deactivated }}</td>
					</tr>
				</tbody>
			</table>
		</NcSettingsSection>

		<NcSettingsSection :name="t('dkmunicipalorganisation', 'Access control')">
			<p>{{ t('dkmunicipalorganisation', 'Settings for access control.') }}</p>

			<NcCheckboxRadioSwitch id="ac-enable"
				v-model="accessControlEnable"
				type="switch">
				{{ t('dkmunicipalorganisation', 'Enable') }}
			</NcCheckboxRadioSwitch>

			<table class="dkmunorg-cert-table">
				<tr>
					<td class="dkmunorg-cert-label">
						<label for="ac-idp-metadata">{{ t('dkmunicipalorganisation', 'Metadata for Context Handler') }}</label>
					</td>
					<td>
						<input id="ac-idp-metadata"
							v-model="idpMetadataUrl"
							type="text"
							:style="{ width: '600px', maxWidth: '100%', boxSizing: 'border-box' }"
							@change="saveConfigValue('idp_metadata_url', idpMetadataUrl)">
					</td>
				</tr>
			</table>

			<div class="dkmunorg-button-row">
				<button class="primary" @click="downloadMetadata">
					{{ t('dkmunicipalorganisation', 'Download metadata file') }}
				</button>
			</div>

			<table class="dkmunorg-roles-table">
				<caption>{{ t('dkmunicipalorganisation', 'Create these user system roles in the Joint Municipal Administration Module') }}</caption>
				<thead>
					<tr>
						<th>{{ t('dkmunicipalorganisation', 'Name') }}</th>
						<th>{{ t('dkmunicipalorganisation', 'EntityId') }}</th>
						<th>{{ t('dkmunicipalorganisation', 'Data delimitation types') }}</th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td>{{ t('dkmunicipalorganisation', 'User') }}</td>
						<td>http://{{ domain }}/roles/usersystemrole/user/1</td>
						<td>{{ t('dkmunicipalorganisation', 'Organisation') }}</td>
					</tr>
					<tr>
						<td>{{ t('dkmunicipalorganisation', 'System Administrator') }}</td>
						<td>http://{{ domain }}/roles/usersystemrole/systemadministrator/1</td>
						<td>{{ t('dkmunicipalorganisation', 'None') }}</td>
					</tr>
				</tbody>
			</table>
		</NcSettingsSection>
	</div>
</template>

<script>
import axios from '@nextcloud/axios'
import { loadState } from '@nextcloud/initial-state'
import { translate as t } from '@nextcloud/l10n'
import { generateUrl } from '@nextcloud/router'
import NcCheckboxRadioSwitch from '@nextcloud/vue/dist/Components/NcCheckboxRadioSwitch.js'
import NcSettingsSection from '@nextcloud/vue/dist/Components/NcSettingsSection.js'

export default {
	name: 'AdminSettings',
	components: {
		NcCheckboxRadioSwitch,
		NcSettingsSection,
	},
	computed: {
		domain() {
			return window.location.hostname
		},
		certExpiresFormatted() {
			if (!this.certExpiresAt) {
				return ''
			}
			const date = new Date(this.certExpiresAt * 1000)
			return date.toLocaleDateString('da-DK', { year: 'numeric', month: 'long', day: 'numeric' })
		},
	},
	data() {
		const certificate = loadState('dkmunicipalorganisation', 'certificate', { filepath: '', password: '' })
		const config = loadState('dkmunicipalorganisation', 'config', {})
		const syncLog = loadState('dkmunicipalorganisation', 'syncLog', [])
		const prerequisites = loadState('dkmunicipalorganisation', 'prerequisites', {})
		return {
			groupfoldersEnabled: prerequisites.groupfolders || false,
			syncLog,
			filepath: certificate.filepath,
			password: certificate.password,
			certSubject: '',
			certSerialNumber: '',
			certExpiresAt: 0,
			certError: '',
			accessControlEnable: config.access_control_enable === '1',
			idpMetadataUrl: config.idp_metadata_url || '',
			organisationEnable: config.organisation_enable === '1',
			cvr: config.cvr || '',
			tokenIssuerBaseUrl: config.token_issuer_base_url || '',
			entityIdOrganisation: config.entity_id_organisation || '',
			endpointOrganisation: config.endpoint_organisation || '',
			syncing: false,
			syncResult: null,
			syncError: '',
		}
	},
	watch: {
		accessControlEnable(value) {
			this.saveConfigValue('access_control_enable', value ? '1' : '0')
		},
		organisationEnable(value) {
			this.saveConfigValue('organisation_enable', value ? '1' : '0')
		},
	},
	mounted() {
		if (this.filepath && this.password) {
			this.validateCertificate()
		}
	},
	methods: {
		t,
		async saveConfigValue(key, value) {
			try {
				await axios.post(
					generateUrl('/apps/dkmunicipalorganisation/settings/config'),
					{ key, value },
				)
			} catch (e) {
				console.error('Failed to save config', e)
			}
		},
		downloadMetadata() {
			window.location.href = generateUrl('/apps/dkmunicipalorganisation/saml/metadata')
		},
		async syncOrganisations() {
			this.syncing = true
			this.syncResult = null
			this.syncError = ''
			try {
				const response = await axios.post(
					generateUrl('/apps/dkmunicipalorganisation/settings/sync-organisations'),
				)
				this.syncResult = response.data
			} catch (e) {
				this.syncError = t('dkmunicipalorganisation', 'Synchronization failed')
				console.error('Sync failed', e)
			} finally {
				this.syncing = false
			}
		},
		async validateCertificate() {
			this.certSubject = ''
			this.certSerialNumber = ''
			this.certExpiresAt = 0
			this.certError = ''

			try {
				const response = await axios.post(
					generateUrl('/apps/dkmunicipalorganisation/settings/certificate/validate'),
					{
						filepath: this.filepath,
						password: this.password,
					},
				)
				if (response.data.valid) {
					this.certSubject = response.data.subject
					this.certSerialNumber = response.data.serialNumber
					this.certExpiresAt = response.data.expiresAt
				} else {
					this.certError = response.data.error
				}
			} catch (e) {
				this.certError = 'cannot_read'
			}
		},
	},
}
</script>

<style>
.dkmunorg-cert-table {
	margin-top: 12px;
	border-collapse: separate;
	border-spacing: 0 8px;
}

.dkmunorg-cert-label {
	font-weight: bold;
	padding-right: 16px;
	white-space: nowrap;
	vertical-align: middle;
}

.certificate-error {
	margin-top: 12px;
	padding: 12px 16px;
	background-color: var(--color-error, #e9322d);
	background-color:  #e9322d;
	color: #fff;
	font-weight: bold;
	border-radius: 8px;
	display: inline-block;	
}

.dkmunorg-cert-info-box {
	margin-top: 12px;
	padding: 12px 16px;
	background-color: var(--color-success, #D8F3DA);
	background-color: #D8F3DA;
	color: #000;
	border-radius: 8px;
	display: inline-block;
}

.dkmunorg-cert-info-box div {
	margin: 4px 0;
}

.dkmunorg-button-row {
	margin-top: 16px;
}

.dkmunorg-sync-log-table {
	margin-top: 16px;
	border-collapse: collapse;
	width: 100%;
	max-width: 600px;
}

.dkmunorg-sync-log-table caption {
	text-align: left;
	font-weight: bold;
	margin-bottom: 8px;
}

.dkmunorg-sync-log-table th,
.dkmunorg-sync-log-table td {
	padding: 8px 12px;
	text-align: left;
	border-bottom: 1px solid var(--color-border, #ddd);
}

.dkmunorg-sync-log-table th {
	font-weight: bold;
	background-color: var(--color-background-dark, #f5f5f5);
}

.dkmunorg-sync-log-table tbody tr:hover {
	background-color: var(--color-background-hover, #f0f0f0);
}

.dkmunorg-roles-table {
	margin-top: 24px;
	border-collapse: collapse;
	width: 100%;
}

.dkmunorg-roles-table caption {
	text-align: left;
	font-weight: bold;
	margin-bottom: 8px;
}

.dkmunorg-roles-table th,
.dkmunorg-roles-table td {
	padding: 8px 12px;
	text-align: left;
	border-bottom: 1px solid var(--color-border, #ddd);
}

.dkmunorg-roles-table th {
	font-weight: bold;
	background-color: var(--color-background-dark, #f5f5f5);
}

.dkmunorg-roles-table tbody tr:hover {
	background-color: var(--color-background-hover, #f0f0f0);
}

.dkmunorg-prerequisite {
	margin: 4px 0;
	font-size: 14px;
}

.dkmunorg-check {
	color: #2ea043;
	font-weight: bold;
	margin-right: 8px;
}

.dkmunorg-cross {
	color: #e9322d;
	font-weight: bold;
	margin-right: 8px;
}
</style>
