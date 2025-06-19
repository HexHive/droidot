#!/bin/bash

adb install termux.apk
sleep 2
adb push termux_install.sh /data/local/tmp/
adb shell su root 'chmod +x /data/local/tmp/termux_install.sh'
adb shell su root 'sh /data/local/tmp/termux_install.sh'

echo "==============================================================================================================="
echo "==============================================================================================================="
echo "if all went well save a snapshot of the emulator:"
echo "adb emu avd snapshot save androlib0"
echo "adb emu kill"
echo "next time if you want to start another instance of the ready-to-use emulator use:"

echo "emulator @pixel -no-window -no-audio -skip-adb-auth -no-boot-anim -show-kernel -snapshot androlib0 -read-only"
echo "==============================================================================================================="
echo "==============================================================================================================="
