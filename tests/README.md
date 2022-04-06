# Developing tests

Some tests require a docker registry running locally on port 5000 as well as
some images built.

```
docker run -d -p 5000:5000 --name registry registry:2

for distro in alpine centos debian; do
  docker build -t localhost:5000/match-coverage/$distro ./tests/fixtures/image-$distro-match-coverage
  docker push localhost:5000/match-coverage/$distro:latest
done
```

Then, just run:

```
npm test
```
