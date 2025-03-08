#!/bin/bash

docker build . -f ./scripts/static.Dockerfile --target=test-glibc2.34 --progress=plain
