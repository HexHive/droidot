#!/bin/bash
# this scirpt only work on x64_86 linux

apt-get -y install cmake build-essential

if [ ! -d "AFLplusplus" ] ; then
    git clone https://github.com/AFLplusplus/AFLplusplus.git
fi

cp CMakeLists.txt AFLplusplus/

if [ ! -d "android-ndk-r25c" ] ; then 
    curl https://dl.google.com/android/repository/android-ndk-r25c-linux.zip --output ndk.zip
    unzip ndk.zip
    rm ndk.zip
fi

cd AFLplusplus
mkdir -p build
cd build 

echo "make sure to add __afl_area_ptr to frida.map"

cmake -DANDROID_PLATFORM=28 -DCMAKE_TOOLCHAIN_FILE=../../android-ndk-r25c/build/cmake/android.toolchain.cmake -DANDROID_ABI=arm64-v8a ..

make

cp afl-fuzz ../..
cp afl-frida-trace.so ../..



cp afl-showmap ../..
