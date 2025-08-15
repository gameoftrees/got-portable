#!/bin/sh

set -xv
SUDO="sudo"
export SUDO

which_ci() {
	if [ -n "$RUNNER_OS" ]; then
		# GitHub Actions
		case "$RUNNER_OS" in
		Linux)
			unset SUDO
			echo "linux" ;;
		esac
	elif [ -n "$CIRRUS_OS" ]; then
		# Cirrus CI
		echo "$CIRRUS_OS"
	fi
}

OS="$(which_ci)"

echo "CI_OS=$CI_OS"

if [ "$OS" = "linux" ]; then
	if [ "$CI_OS" == "alpine" ]; then
		apk add libevent-dev git build-base bsd-compat-headers bison automake make autoconf libbsd-dev util-linux-dev libressl-dev zlib-dev ncurses-dev openssh ed gcc clang
	else 
	"$SUDO" apt-get update -qq && \
	"$SUDO" apt-get --no-install-suggests --no-install-recommends -y install \
		athena-jot \
		autoconf \
		autoconf-archive \
		automake \
		autotools-dev \
		bison \
		build-essential \
		ed \
		clang \
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
fi

if [ "$OS" = "freebsd" ]; then
	pkg install -y \
		automake \
		pkgconf \
		git \
		libevent \
		libretls \
		p5-HTTP-Daemon \
		p5-HTTP-Daemon-SSL
fi

if [ "$OS" = "darwin" ]; then
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
