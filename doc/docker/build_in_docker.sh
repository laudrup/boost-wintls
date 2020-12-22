#!/bin/bash -e

DOCKER_DIR=$(dirname "$BASH_SOURCE")
REPO_ROOT=$(git rev-parse --show-toplevel)
IMAGE_NAME=wintls-documentation

docker build -t ${IMAGE_NAME} ${DOCKER_DIR}
docker run -ti -v ${REPO_ROOT}:/wintls -e GITHUB_WORKSPACE=/wintls ${IMAGE_NAME}
