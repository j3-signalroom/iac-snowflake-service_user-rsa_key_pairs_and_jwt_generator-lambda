FROM public.ecr.aws/lambda/python:3.11

RUN yum -y install openssl

# Copy code from host into the container
COPY app.py ${LAMBDA_TASK_ROOT}

CMD ["app.lambda_handler"]
