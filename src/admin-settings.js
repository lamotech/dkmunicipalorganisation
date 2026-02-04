import Vue from 'vue'
import AdminSettings from './AdminSettings.vue'

Vue.mixin({ methods: { t, n } })

const View = Vue.extend(AdminSettings)
new View().$mount('#dkmunicipalorganisation-admin-settings')
