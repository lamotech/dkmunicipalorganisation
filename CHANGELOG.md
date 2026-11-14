# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.3] - 2026-11-12

### Security

- The system certificate password is now stored encrypted with `OCP\Security\ICrypto` instead of in plain text. Existing passwords are encrypted automatically on upgrade.
- The certificate password is no longer sent to the browser on the admin settings page.
- The certificate file is copied into the app's data folder (IAppData) when registered, instead of being read from an arbitrary path. Existing certificates are copied automatically on upgrade.
- Removed the unused web endpoint for saving a certificate path and password. Certificates are registered only with `occ dkmunicipalorganisation:register-certificate`.
- The certificate validation endpoint no longer accepts a file path or password; it validates only the registered certificate.

### Changed

- `occ dkmunicipalorganisation:register-certificate` offers to delete the original `.p12` file after registration.
- The installation guide describes file permissions for the `.p12` file.

### Added

- First release
