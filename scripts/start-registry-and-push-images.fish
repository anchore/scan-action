#!/usr/bin/env fish

# Start the Docker registry
docker run -d -p 5000:5000 --name registry registry:2

# Loop over the distros and build/push images
for distro in alpine centos debian
    docker build -t localhost:5000/match-coverage/$distro ./tests/fixtures/image-$distro-match-coverage
    docker push localhost:5000/match-coverage/$distro:latest
end
