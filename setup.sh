#!/bin/sh

wget https://zenodo.org/records/15586319/files/com.termux.tar.gz?download=1
mv com.termux.tar.gz emulator/
wget https://zenodo.org/records/15586319/files/emulator_dist.tar.gz?download=1
docker build . -t droidot
