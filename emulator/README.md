# Android Fuzzing Emulator

Set up the emulator to use for fuzzing
interact with it just via adb

# Setup

```bash
# get files.tar.gz from: https://drive.google.com/file/d/1g0zp4M04MqY0oJggFkBewcuzLuQSec-l/view?usp=share_link
# unpack files.tar.gz. the following folders should now be here: avd/, emulator/, termux.apk (only emulator is needed)
./install_emulator.sh # tested on aws ec2 arm64 a1.metal instance 
emulator @pixel -no-window -no-audio -skip-adb-auth -no-boot-anim -show-kernel
# wait until booted + few minutes, if there are issues just keep rerunning the script until all is installed :)
./setup_emulator.sh
# if all went well make snapshot and kill instance
adb emu avd snapshot save androlib0
adb emu kill
# now start new instances of the emulator with:
emulator @pixel -no-window -no-audio -skip-adb-auth -no-boot-anim -show-kernel -snapshot androlib0 -read-only
```

## Start emulator

```bash
emulator @pixel -no-window -no-audio -skip-adb-auth -no-boot-anim -show-kernel -snapshot androlib0 -read-only
```

# If you need more than 16 emulators

Use the qemu-system-aarch64-headless binary and replace it in /opt/androidsdk/emulator/qemu/linux-aarch64/
It was hand-patched to support more emulators 

# Hopefully you dont' need this

### Setup Emulator with AFL etc

https://github.com/termux/termux-app/issues/924

```
am start -n com.termux/.app.TermuxActivity
input text "env > termux-env" && input keyevent 113 && input keyevent 66
# get the uid of the termux process
cd /data/data/com.termux/files/home && su [termux uid] && . ./termux-env
pkg update
pkg install gdb
pkg install vim
pkg install git
git clone https://github.com/paocela/AFLplusplus-AndroidPatches.git
git clone https://github.com/paocela/AFLplusplus-AndroidPatches
cd AFLplusplus-AndroidPatches
./clang-v13/install_clang-v13.sh # (chmod a+x if needed)
# in case it fails, run `apt --fix-broken install` and retry
export LD_PRELOAD=$(pwd)/libLLVM-13.so
make
# exit out of adb
adb emu avd snapshot save androlibXX
adb emu kill
# Now by copying the pixel.avd pixel.ini files from ~/.android/avd/ it should be possible to reuse the snapshot of the emulator
```

To test the performance, use the following commands

```
adb shell
su
cd  /data/local/tmp/perf # set this up yourself
PATH=//data/data/com.termux/files/usr/bin:/data/data/com.termux/files/home/AFLplusplus-AndroidPatches:$PATH
# based on the type of test 
# harness_nothing.cpp: literally just forks and exits, harness_bare.cpp: does the jvm and exits, harness_hack.cpp: does the unmapping hack
cp harness_bare.cpp harness.cpp
./compile_harness.sh .
AFL_FORKSRV_INIT_TMOUT=99999999999 LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/{app}/lib/arm64-v8a:/system/lib64 afl-fuzz -i seeds -o output -- ./harness @@
```

### Performance

Honeycomb001:

harness_nothing: 1140
harness_hack: 510
harness_bare: 150
