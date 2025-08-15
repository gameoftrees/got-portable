#!/bin/sh

if [ "$CIRRUS_OS" = "linux" ]; then
	apt-get update -qq && \
	apt-get --no-install-suggests --no-install-recommends -y install \
		athena-jot \
		autoconf \
		autoconf-archive \
		automake \
		autotools-dev \
		bison \
		build-essential \
		ed \
		git \
		libbsd-dev \
		libevent-dev \
		libhttp-daemon-perl \
		libhttp-daemon-ssl-perl \
		libncurses5-dev \
		libssl-dev \
		libtls-dev \
		pkg-config \
		uuid-dev \
		zlib1g-dev
fi

if [ "$CIRRUS_OS" = "freebsd" ]; then
	pkg install -y \
		automake \
		pkgconf \
		git \
		libevent \
		libretls \
		p5-HTTP-Daemon \
		p5-HTTP-Daemon-SSL
fi

if [ "$CIRRUS_OS" = "darwin" ]; then
	brew install autoconf \
		automake \
		bison \
		pkg-config \
		ncurses \
		ossp-uuid \
		git \
		libevent \
		libretls
fi
