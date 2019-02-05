#!/usr/bin/env bash
set -e # Fail fast on error

export SHA=$(git rev-parse HEAD | cut -c 1-7)
export REPOSITORY=ncsa-hmac
echo "Building test image for SHA: ${SHA}"

if [[ "$(docker images -q $REPOSITORY:testsuite-$SHA 2> /dev/null)" == "" ]]; then
  echo "Test source image absent, recreating"
  docker build -t "$REPOSITORY:testsuite-$SHA" -f script/test.Dockerfile .
fi

echo "Using: ${REPOSITORY}:testsuite-${SHA} and running the test suite"
docker run --rm --name "$REPOSITORY-test" "$REPOSITORY:testsuite-$SHA"
