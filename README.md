# Danish Municipal Organisation and Access Control

In Denmark the organisation KOMBIT provides shared shared service integrations for public mulicipalities.

This app features integrations to the 2 most basic services:

- Organisation structure
- Access control through SAML login flow.


## Requirements

This app requires the Team Folder app to be installed. The integration to the organisation structure create a tem folder for each department in the organisation structure where the sers can collabrorate on documents.


## Configurations

### System certificate

The integrations requires an official certificate (.p12 file) issues by the Danish goverment. Once you have aquired the certificate from MitId Business portal it must be copied to the Nextcloud server. Then you can run this command to register it with the app:

php occ dkmunicipalorganisation:register-certificate

The command will ask you for path to certificate file and the password.

### Register IT system at Serviceplatformen
To use the integraatiopn you must register your Nextcloud system as an IT system at Serviceplatformen administration portal and upload the public key of your certificate.

### Organisation structure integration
It requeris a service agreement with Serviceplatformen to use the organisation sysn service.

### Access control
To configure the SAML login flow you can download the SAMl metadata file from the app config page in Nextcloud.
