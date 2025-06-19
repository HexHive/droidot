#!/bin/bash

set -euxo pipefail

apt-get update
apt-get install -y default-jdk default-jre wget python3 python3-pip vim unzip adb
wget https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip

export ANDROID_HOME=/opt/androidsdk
mkdir -p $ANDROID_HOME
mkdir $ANDROID_HOME/cmdline-tools
unzip commandlinetools-linux-9477386_latest.zip -d $ANDROID_HOME/cmdline-tools

echo "export ANDROID_HOME=$ANDROID_HOME" >> ~/.bashrc
echo 'export SDK=$ANDROID_HOME' >> ~/.bashrc
echo 'export PATH=$SDK/emulator:$SDK/tools:$SDK/cmdline-tools/latest/bin:$SDK/platform-tools:$PATH' >> ~/.bashrc
source ~/.bashrc

export PATH="$PATH:$ANDROID_HOME/emulator:$ANDROID_HOME/tools:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools"
export ANDROID_SDK="/opt/androidsdk/"
mkdir /opt/androidsdk/cmdline-tools/latest
mv -T /opt/androidsdk/cmdline-tools/cmdline-tools /opt/androidsdk/cmdline-tools/latest

# RUN yes | sdkmanager "platforms;android-32"

# 33.1.10

# TODO add lov priv user (RUN chmod 0777 /dev/kvm)
#chmod +x ./docker_entrypoint.sh
apt-get install -y android-sdk-platform-tools
cp -R emulator/ /opt/androidsdk/emulator/
yes | sdkmanager "system-images;android-30;aosp_atd;arm64-v8a"
mkdir -p /opt/androidsdk/platforms
mkdir /opt/androidsdk/platform-tools
avdmanager create avd -n pixel -d pixel_2_xl -k "system-images;android-30;aosp_atd;arm64-v8a"
echo "Vulkan = off" >> /root/.android/advancedFeatures.ini
echo "GLDirectMem = on" >> /root/.android/advancedFeatures.ini

echo "==============================================================================================================="
echo "==============================================================================================================="
echo "now start the emulator like this and wait until booted (wait at least a minute after the message)"
echo "then run the setup_emulator.sh script"
echo "emulator @pixel -no-window -no-audio -skip-adb-auth -no-boot-anim -show-kernel"
echo "./setup_emulator.sh"
echo "==============================================================================================================="
echo "==============================================================================================================="