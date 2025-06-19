#!/bin/sh

wget https://zenodo.org/records/15697750/files/com.termux.tar.gz
mv com.termux.tar.gz emulator/
wget https://zenodo.org/records/15697750/files/emulator_dist.tar.gz
wget https://zenodo.org/records/15700199/files/target_APK.tar.gz
tar xvf target_APK.tar.gz
docker build . -t droidot
