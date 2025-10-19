# Changelog
All notable changes to this project will be documented in this file.

The format is base on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [1.00.00.000] - TBD
### Changed
- Issue [#145](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/145)
- Issue [#150](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/150)
- Issue [#152](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/152)

## [0.50.00.000] - 2025-08-08
### Added
- Issue [#100](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/100)
- Issue [#107](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/107)
- Issue [#121](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/121)
- Issue [#132](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/132)
- Issue [#143](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/143)

### Changed
- Issue [#103](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/103)
- Issue [#110](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/110)
- Issue [#119](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/119)
- Issue [#130](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/130)
- Issue [#140](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/140)

### Fixed
- Issue [#134](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/134)
- Issue [#138](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/138)

## [0.49.00.000] - 2025-07-17
### Added
- Issue [#95](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/95)

## [0.48.00.000] - 2025-07-17
### Fixed
- Issue [#91](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/91)

## [0.47.00.000] - 2025-07-17
### Added
- Issue [#89](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/89)

## [0.46.00.000] - 2025-07-15
### Fixed
- Issue [#87](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/87)

## [0.45.00.000] - 2025-07-15
### Added
- Issue [#85](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/85)

## [0.44.01.000] - 2025-06-02
### Changed
- Issue [#81](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/81)

## [0.44.00.000] - 2025-05-16
### Added
- Issue [#78](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/78)

### Fixed
- Issue [#76](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/76)

## [0.43.02.000] - 2025-05-16
### Changed
- Issue [#73](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/73)

## [0.43.01.000] - 2025-05-15
### Added
- Issue [#71](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/71)

### Fixed
- Issue [#69](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/69)

## [0.43.00.000] - 2025-04-22
### Changed
- Issue [#67](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/67)

### Fixed
- Issue [#65](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/65)

## [0.42.00.000] - 2025-04-21
### Fixed
- Issue [#63](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/63)

## [0.41.00.000] - 2024-12-10
### Added
- Issue [#61](https://github.com/j3-signalroom/iac-snowflake-service_user-rsa_key_pairs_and_jwt_generator-lambda/issues/61)

## [0.40.00.000] - 2024-09-06
### Added
- Able to customize the secrets path.

## [0.30.00.000] - 2024-09-04
### Changed
- The lambda function should only update the secrets, never create them, because the Terraform module needs to handle that task in order for Terraform to manage the creation and destruction of the secrets.

## [0.22.00.000] - 2024-09-04
### Changed
- Ensure newlines, carriage returns, and spaces are not in the `rsa_public_key_1` and `rsa_public_key_2` fields.
- Force rebuild of docker container on every run.

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