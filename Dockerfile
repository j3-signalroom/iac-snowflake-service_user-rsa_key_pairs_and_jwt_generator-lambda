FROM public.ecr.aws/lambda/python:3.11.2024.11.22.15

# Container metadata
LABEL maintainer=j3@thej3.com \
      description="IaC Snowflake User RSA Key Pairs Generator Lambda"

# Copy code from host into the container
COPY app.py ${LAMBDA_TASK_ROOT}

# install packages
RUN python3 -m pip install "cryptography>=44.0.2"
RUN python3 -m pip install "boto3>=1.35.36"
RUN python3 -m pip install "setuptools>=65.5.1"

# Set the entrypoint for the container
CMD ["app.lambda_handler"]
