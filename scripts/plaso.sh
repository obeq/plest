#!/bin/bash

echo $(pwd)
docker run -v $(pwd)/testdata/:/data log2timeline/plaso log2timeline $@