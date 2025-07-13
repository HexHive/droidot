FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && apt-get upgrade -y
RUN apt install -y \
	python3-pip \
	adb \
	vim \
	graphviz-dev \
	openjdk-8-jdk \
	wget \
	libpcre2-dev

COPY requirements.txt /requirements.txt
RUN pip3 install -r /requirements.txt --break-system-packages

ENV PS1="\u@\h:\w\$ "


# https://gist.github.com/nhtua/2d294f276dc1e110a7ac14d69c37904f
#RUN apt-get update; apt-get install -y default-jdk; apt-get -y install default-jre pulseaudio
RUN wget https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip
ENV ANDROID_HOME=/opt/androidsdk
RUN mkdir -p $ANDROID_HOME
RUN mkdir $ANDROID_HOME/cmdline-tools
RUN apt-get install unzip -y && unzip commandlinetools-linux-9477386_latest.zip  -d $ANDROID_HOME/cmdline-tools

RUN echo "export ANDROID_HOME=$ANDROID_HOME" >> ~/.bashrc;echo 'export SDK=$ANDROID_HOME' >> ~/.bashrc;echo 'export PATH=$SDK/emulator:$SDK/tools:$SDK/cmdline-tools/latest/bin:$SDK/platform-tools:$PATH' >> ~/.bashrc
SHELL ["/bin/bash", "-c"]
RUN source ~/.bashrc

ENV PATH="$PATH:$ANDROID_HOME/emulator:$ANDROID_HOME/tools:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools"
RUN mkdir /opt/androidsdk/cmdline-tools/latest
RUN mv -T /opt/androidsdk/cmdline-tools/cmdline-tools /opt/androidsdk/cmdline-tools/latest

COPY emulator_dist.tar.gz /opt/androidsdk/
RUN cd /opt/androidsdk/  && tar xvf ./emulator_dist.tar.gz
COPY emulator/package.xml /opt/androidsdk/emulator/

RUN apt install -y default-jdk
RUN yes | sdkmanager "platform-tools" "platforms;android-30"
RUN yes | sdkmanager "system-images;android-30;aosp_atd;arm64-v8a"

RUN avdmanager create avd -n pixel -d pixel_2_xl -k "system-images;android-30;aosp_atd;arm64-v8a"

RUN echo "Vulkan = off" >> ~/.android/advancedFeatures.ini
RUN echo "GLDirectMem = on" >> ~/.android/advancedFeatures.ini
RUN rm /opt/androidsdk/emulator/crashpad_handler 

RUN rm /opt/androidsdk/platform-tools/adb

RUN wget https://github.com/skylot/jadx/releases/download/v1.5.2/jadx-1.5.2.zip
RUN unzip jadx-1.5.2.zip -d /usr

RUN apt-get install -y docker.io

RUN ln -sf /opt/androidsdk/platforms /usr/lib/android-sdk/platforms

RUN sdkmanager "platforms;android-19" "platforms;android-20" "platforms;android-21" \
           "platforms;android-22" "platforms;android-23" "platforms;android-24" \
           "platforms;android-25" "platforms;android-26" "platforms;android-27" \
           "platforms;android-28" "platforms;android-29" "platforms;android-30" \
           "platforms;android-31" "platforms;android-32"
