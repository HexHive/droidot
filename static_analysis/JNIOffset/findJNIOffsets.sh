#!/system/bin/sh

# little script to start the jniOffsetFinder. needed because I need to set env variables

APP=$1
LIBRARY=$2
REMFOLDER=$3
LDPRELOAD=$4

cd $REMFOLDER
export LD_PRELOAD="/data/data/com.termux/files/usr/lib/libc++_shared.so "$4
export LD_LIBRARY_PATH="/apex/com.android.art/lib64:$(pwd):$(pwd)/$APP/lib/arm64-v8a:/system/lib64"
./jniOffsetFinder $APP $LIBRARY
echo "RETURN CODE $?"