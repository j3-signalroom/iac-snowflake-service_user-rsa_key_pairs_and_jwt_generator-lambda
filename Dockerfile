FROM public.ecr.aws/lambda/python:3.11

RUN yum -y install openssl

# Copy code from host into the container
COPY app.py .

CMD ["lambda_handler"]
