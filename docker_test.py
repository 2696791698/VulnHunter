import docker

PROJECT_ROOT = "/home/houning/Projects/dataset/qwq"

client = docker.from_env()

container = client.containers.run(
    image="mcr.microsoft.com/devcontainers/anaconda:3",
    command="sleep infinity",
    detach=True,
    name="anaconda-container",
    volumes={
        PROJECT_ROOT: {
            "bind": "/workspace",
            "mode": "rw",
        }
    },
    working_dir="/workspace",
)

container.stop()
container.remove()