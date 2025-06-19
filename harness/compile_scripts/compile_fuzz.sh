#!/system/bin/sh
PATH_TO_TERMUX_BIN="/data/data/com.termux/files/usr/bin"

REMFOLDER=$1

cd $REMFOLDER

rm libharness.so
rm harness

export PATH=$PATH_TO_TERMUX_BIN:$PATH
g++ -std=c++17 -fPIC -Wall -shared libharness.cpp -o libharness.so
g++ -std=c++17 -L. -lharness -Wall -std=c++17 -Wl,--export-dynamic harness.cpp -o harness