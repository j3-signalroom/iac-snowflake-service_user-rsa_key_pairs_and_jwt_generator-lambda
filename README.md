# IaC Snowflake User RSA Key Generator
Use this AWS Lambda function, written in Python, to generate two new [RSA key pairs](https://github.com/j3-signalroom/j3-techstack-lexicon/blob/main/cryptographic-glossary.md#rsa-key-pair) for a specific Snowflake user. After generation, the function automatically stores the RSA key pairs securely in your AWS Secrets Manager. This ensures the keys can be safely retrieved and managed for future use by the Snowflake user.

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
    git clone https://github.com/j3-signalroom/iac-snowflake-user-rsa_key_pair_generator-lambda.git
    ```

3. From the root folder of the `iac-snowflake-user-rsa_key_pair_generator-lambda/` repository that you cloned, run the script in your Terminal to publish the RSA key pair generator AWS Lambda Docker container to your AWS ECR:
    ```shell
    scripts/run-locally.sh <create | delete> --profile=<SSO_PROFILE_NAME>
    ```
    Argument placeholder|Replace with
    -|-
    `<SSO_PROFILE_NAME>`|your AWS SSO profile name for your AWS infrastructue that houses your AWS Secrets Manager.
