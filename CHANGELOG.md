# Changelog
All notable changes to this project will be documented in this file.

The format is base on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.21.00.000] - 2024-08-28
### Fixed
- Tweaked the name of the repo, and fixed a potential problem with the delete command of the script. 

### Changed
- Script is not responsible for delete AWS Secrets Manager secrets.

## [0.20.00.000] - 2024-08-27
### Added
- Now create two RSA key pairs per Snowflake user.

### Changed
- Updated the `README.md` to be more instructive.

## [0.10.00.000] - 2024-08-26
### Changed
- Removed Terraform entirely from this repo because Terraform was not unnecessary; instead, I added the Terraform configuration to the rotation module.

## [0.01.00.000] - 2024-08-26
### Added
- First release.