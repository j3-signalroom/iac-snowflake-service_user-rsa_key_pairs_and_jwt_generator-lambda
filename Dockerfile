FROM public.ecr.aws/lambda/python:3.11

RUN yum -y install openssl

# Setup the /app working folder
RUN mkdir /app

# Copy code from host into the /app folder on the container
COPY app.py /app
WORKDIR /app

# Create User Group with newly created Rootless System Account as a member.  The new member 
# doesn't have a shell (i.e., home directory)
RUN groupadd -r app_runner && useradd -r -s /bin/false -g app_runner app_runner

# Giving the newly created users permission to the application folder ONLY
RUN chown -R app_runner:app_runner /app

# Change the Home directory of the app_runner user
RUN usermod -d /app app_runner

# Start the Python application with the newly created user
USER app_runner

CMD ["python", "app.lambda_handler"]
