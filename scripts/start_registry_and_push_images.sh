#!/usr/bin/env bash
set -euo pipefail

# Remove existing container named 'registry' if it exists
if docker ps -a --format '{{.Names}}' | grep -Eq '^registry$'; then
  echo "Removing existing 'registry' container..."
  docker rm -f registry
fi

# Start a new registry container
docker run -d -p 5000:5000 --name registry registry:2

# Build and push images
for distro in alpine centos debian; do
  docker build -t localhost:5000/match-coverage/$distro ./tests/fixtures/image-$distro-match-coverage
  docker push localhost:5000/match-coverage/$distro:latest
done
