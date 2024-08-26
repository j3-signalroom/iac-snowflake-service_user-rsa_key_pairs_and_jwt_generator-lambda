# IaC Snowflake User RSA Key Generator
This AWS Lambda function, developed in Python, is designed to generate a new [RSA key pair](https://github.com/j3-signalroom/j3-techstack-lexicon/blob/main/cryptographic-glossary.md#rsa-key-pair) specifically for a Snowflake service account user.  The generated RSA public and private key is securely stored in AWS Secrets Manager, ensuring safe retrieval and management of the key for future use by the Snowflake service.

**Table of Contents**

<!-- toc -->
+ [1.0 Let's get started!](#10-lets-get-started)
<!-- tocstop -->

## 1.0 Let's get started!
1. Take care of the cloud and local environment prequisities listed below:
    > You need to have the following cloud accounts:
    > - [AWS Account](https://signin.aws.amazon.com/) *with SSO configured*
    > - [`aws2-wrap` utility](https://pypi.org/project/aws2-wrap/#description)

    > You need to have the following installed on your local machine:
    > - [AWS CLI version 2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)

2. Clone the repo:
    ```shell
    git clone https://github.com/j3-signalroom/iac-snowflake_user-rsa_key_generator.git
    ```

3. From the root folder of the `iac-snowflake_user-rsa_key_generator/` repository that you cloned, run the script in your Terminal to publish the RSA Key Generator AWS Lambda Docker container to your AWS ECR:
    ```shell
    scripts/run-terraform-locally.sh <create | delete> --profile=<SSO_PROFILE_NAME>
    ```
    Argument placeholder|Replace with
    -|-
    `<SSO_PROFILE_NAME>`|your AWS SSO profile name for your AWS infrastructue that houses your AWS Secrets Manager.
