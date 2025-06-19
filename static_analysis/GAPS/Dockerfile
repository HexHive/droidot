# syntax=docker/dockerfile:latest
ARG UBUNTU_VERSION=jammy
ARG BAKSMALI_URL=https://bitbucket.org/JesusFreke/smali/downloads/baksmali-2.5.2.jar
ARG BAKSMALI_WRAPPER_URL=https://bitbucket.org/JesusFreke/smali/downloads/baksmali
ARG ANDROID_TOOLS_URL=https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip

################################################################################
# GAPS image
################################################################################
FROM ubuntu:$UBUNTU_VERSION as gaps
ARG BAKSMALI_URL
ARG BAKSMALI_WRAPPER_URL
ARG ANDROID_TOOLS_URL

# Enable APT package caching
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

# Install prerequisites
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        vim \
        unzip \
        build-essential \
        libssl-dev \
        libffi-dev \
        openjdk-18-jdk-headless \
        python3-dev \
        python3-ipdb \
        python3-ipython \
        python3-pip \
	apktool \
	jq

# Install Python dependencies
RUN --mount=type=bind,source=src/requirements.txt,target=/requirements.txt \
    --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip3 install -r /requirements.txt

ENV PYTHONPATH=/opt/src

ADD --link $BAKSMALI_WRAPPER_URL /opt/bin/baksmali
ADD --link $BAKSMALI_URL /opt/bin/baksmali.jar
ADD --link $ANDROID_TOOLS_URL /tmp/commandlinetools.zip
RUN unzip /tmp/commandlinetools.zip -d /opt/android

ENV PATH=$PATH:/opt/android/cmdline-tools/bin

RUN yes | sdkmanager --sdk_root=/opt/android --install 'build-tools;23.0.0'

RUN chmod u+x /opt/bin/baksmali
ENV PATH=$PATH:/opt/bin
ENV PATH=$PATH:/opt/android/build-tools/23.0.0

ENTRYPOINT ["/bin/bash", "-c"]
CMD ["/entrypoint.sh"]
