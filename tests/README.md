# Developing tests

Tests are being implemented in javascript (and soon to be Typescript).
Some tests require a docker registry running locally on port 5000. This is handled
automatically in the Github action tests,
but if you want to run the tests yourself you will need to have docker installed
and run something like:

```
docker run -d -p 5000:5000 --name registry registry:2
```

... or if you run `make bootstrap`, this is automatically handled for you. After
which time, you can just run:

```
npm test
```

Some of the existing tests are written in Python 3 and will
download [act](https://github.com/nektos/act) and create a Python virtual
environment to run them in. To run these locally, from the root directory execute:

```
npm run build
make check
```
