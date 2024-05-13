# Vending Machine

## Command to execute Docker
Build the Docker image: Open a terminal, navigate to the directory containing your Dockerfile and run the following command:
`docker build -t my-fastapi-app .`

Run the Docker container: Once the image is built, you can run a container based on that image:
`docker run -d -p 80:8000 my-fastapi-app`

Rebuild the Docker image
`docker build -t my-fastapi-app:latest .`

Stop Docker container:
`docker stop container_name_or_id`

Remove Docker container:
`docker rm container_name_or_id`