FROM public.ecr.aws/lambda/python:3.11.2024.11.22.15

RUN yum -y update
RUN yum -y install openssl

# Copy code from host into the container
COPY app.py ${LAMBDA_TASK_ROOT}

# install packages
RUN python3 -m pip install "boto3>=1.35.36"
RUN python3 -m pip install "setuptools>=65.5.1"

# Set the entrypoint for the container
CMD ["app.lambda_handler"]
