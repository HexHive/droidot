#!/bin/sh

wget https://zenodo.org/records/15586319/files/emulator_dist.tar.gz?download=1
docker build . -t droidot
