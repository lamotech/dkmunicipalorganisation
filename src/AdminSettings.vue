<template>
	<div class="dkmunorg-admin-settings">
		<NcSettingsSection :name="'Systemcertifikat'">
			<p>Kopier dit systemcertifikat til serveren og angiv stien her.</p>

			<table class="dkmunorg-cert-table">
				<tr>
					<td class="dkmunorg-cert-label">
						<label for="cert-filepath">Sti til systemcertifikat</label>
					</td>
					<td>
						<input id="cert-filepath"
							v-model="filepath"
							type="text"
							:style="{ width: '600px', maxWidth: '100%', boxSizing: 'border-box' }"
							placeholder="/sti/til/certifikat.p12"
							@change="onFieldChange">
					</td>
				</tr>
				<tr>
					<td class="dkmunorg-cert-label">
						<label for="cert-password">Adgangskode</label>
					</td>
					<td>
						<input id="cert-password"
							v-model="password"
							type="password"
							:style="{ width: '200px', maxWidth: '100%', boxSizing: 'border-box' }"
							@change="onFieldChange">
					</td>
				</tr>
			</table>

			<div v-if="saving" class="certificate-status">
				Gemmer...
			</div>
			<div v-else-if="certError === 'not_found'" class="certificate-error">
				Certificatet findes ikke på den angivne sti
			</div>
			<div v-else-if="certError === 'cannot_read'" class="certificate-error">
				Certificatet kan ikke læses
			</div>
			<div v-else-if="certSubject" class="dkmunorg-cert-info-box">
				<div><strong>Navn:</strong> {{ certSubject }}</div>
				<div><strong>Serienummer:</strong> {{ certSerialNumber }}</div>
				<div><strong>Udløber:</strong> {{ certExpiresFormatted }}</div>
			</div>
		</NcSettingsSection>

		<NcSettingsSection :name="'Organisation'">
			<p>Indstillinger for organisationsintegration.</p>

			<NcCheckboxRadioSwitch id="org-enable"
				v-model="organisationEnable"
				type="switch">
				Aktiver
			</NcCheckboxRadioSwitch>

			<table class="dkmunorg-cert-table">
				<tr>
					<td class="dkmunorg-cert-label">
						<label for="org-cvr">CVR nummer</label>
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
						<label for="org-token-url">Token service url</label>
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
						<label for="org-entity-id">Entity id for organisation</label>
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
						<label for="org-endpoint">Endpoint for organisation service</label>
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
					{{ syncing ? 'Synkroniserer...' : 'Synkroniser organisationer nu' }}
				</button>
			</div>
			<div v-if="syncResult" class="dkmunorg-cert-info-box">
				<div><strong>Hentet:</strong> {{ syncResult.fetched }}</div>
				<div><strong>Oprettet:</strong> {{ syncResult.created }}</div>
				<div><strong>Opdateret:</strong> {{ syncResult.updated }}</div>
				<div><strong>Deaktiveret:</strong> {{ syncResult.deactivated }}</div>
			</div>
			<div v-if="syncError" class="certificate-error">
				{{ syncError }}
			</div>
		</NcSettingsSection>

		<NcSettingsSection :name="'Adgangsstyring'">
			<p>Indstillinger for adgangsstyring.</p>

			<NcCheckboxRadioSwitch id="ac-enable"
				v-model="accessControlEnable"
				type="switch">
				Aktiver
			</NcCheckboxRadioSwitch>

			<table class="dkmunorg-cert-table">
				<tr>
					<td class="dkmunorg-cert-label">
						<label for="ac-idp-metadata">Metadata til Context Handler</label>
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
					Download metadata fil
				</button>
			</div>
		</NcSettingsSection>
	</div>
</template>

<script>
import axios from '@nextcloud/axios'
import { loadState } from '@nextcloud/initial-state'
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
		return {
			filepath: certificate.filepath,
			password: certificate.password,
			certSubject: '',
			certSerialNumber: '',
			certExpiresAt: 0,
			certError: '',
			saving: false,
			saveTimeout: null,
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
		onFieldChange() {
			if (this.saveTimeout) {
				clearTimeout(this.saveTimeout)
			}
			this.saveTimeout = setTimeout(() => {
				this.saveCertificate()
			}, 500)
		},
		async saveCertificate() {
			if (!this.filepath) {
				this.certSubject = ''
				this.certSerialNumber = ''
				this.certExpiresAt = 0
				this.certError = ''
				return
			}

			this.saving = true
			this.certSubject = ''
			this.certSerialNumber = ''
			this.certExpiresAt = 0
			this.certError = ''

			try {
				const response = await axios.post(
					generateUrl('/apps/dkmunicipalorganisation/settings/certificate'),
					{
						filepath: this.filepath,
						password: this.password,
					},
				)
				const validation = response.data.validation
				if (validation.valid) {
					this.certSubject = validation.subject
					this.certSerialNumber = validation.serialNumber
					this.certExpiresAt = validation.expiresAt
					this.certError = ''
				} else {
					this.certSubject = ''
					this.certSerialNumber = ''
					this.certExpiresAt = 0
					this.certError = validation.error
				}
			} catch (e) {
				this.certSubject = ''
				this.certSerialNumber = ''
				this.certExpiresAt = 0
				this.certError = 'cannot_read'
			} finally {
				this.saving = false
			}
		},
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
				this.syncError = 'Synkronisering fejlede'
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
	color: var(--color-error, #e9322d);
	font-weight: bold;
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

.certificate-status {
	margin-top: 12px;
	color: var(--color-text-maxcontrast);
}

.dkmunorg-button-row {
	margin-top: 16px;
}
</style>
