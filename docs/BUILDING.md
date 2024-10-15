# Compiling Nerva from Source

**NOTE:** Nerva used build scripts in the past that are inside `nerva/builder/` but we discontinued that in favor of just using `make`. This approach is deprecated and will be removed in a future release.

We will compile using CMake build system. When using `make` to compile, executable files will be created in a directory similar to this:
`nerva/build/[YOUR_SYSTEM]/[YOUR_BRANCH]/release/bin/`

## Table of Contents

- [Dependencies](#dependencies)
- [Install Dependencies](#install-dependencies)
  - [Ubuntu/Debian](#ubuntudebian)
  - [Windows](#windows)
  - [MacOS](#macos)
- [Clone Nerva Repository](#clone-repository)
- [Build](#build)
  - [Linux](#linux)
  - [Windows](#windows)
  - [MacOS](#macos)
  - [Build Options](#build-options)
- [Building portable statically linked binaries](#building-portable-statically-linked-binaries)
- [Cross Compiling](#cross-compiling)
- [Gitian builds](#gitian-builds)

### Dependencies

The following table summarizes the tools and libraries required to build. A
few of the libraries are also included in this repository (marked as
"Vendored"). By default, the build uses the library installed on the system
and ignores the vendored sources. However, if no library is found installed on
the system, then the vendored source will be built and used. The vendored
sources are also used for statically-linked builds because distribution
packages often include only shared library binaries (`.so`) but not static
library archives (`.a`).

| Dep         | Min. version  | Vendored | Debian/Ubuntu pkg    | Arch pkg     | Void pkg              | Fedora pkg          | Optional | Purpose         |
|-------------|---------------|----------|----------------------|--------------|-----------------------|---------------------|----------|-----------------|
| GCC         | 7             | NO       | `build-essential`    | `base-devel` | `base-devel`          | `gcc`               | NO       |                 |
| CMake       | 3.5           | NO       | `cmake`              | `cmake`      | `cmake`               | `cmake`             | NO       |                 |
| pkg-config  | any           | NO       | `pkg-config`         | `base-devel` | `base-devel`          | `pkgconf`           | NO       |                 |
| Boost       | 1.58          | NO       | `libboost-all-dev`   | `boost`      | `boost-devel`         | `boost-devel`       | NO       | C++ libraries   |
| OpenSSL     | basically any | NO       | `libssl-dev`         | `openssl`    | `openssl-devel`       | `openssl-devel`     | NO       | sha256 sum      |
| libzmq      | 4.2.0         | NO       | `libzmq3-dev`        | `zeromq`     | `zeromq-devel`        | `zeromq-devel`      | NO       | ZeroMQ library  |
| OpenPGM     | ?             | NO       | `libpgm-dev`         | `libpgm`     |                       | `openpgm-devel`     | NO       | For ZeroMQ      |
| libnorm[2]  | ?             | NO       | `libnorm-dev`        |              |                       |                     | YES      | For ZeroMQ      |
| libunbound  | 1.4.16        | NO       | `libunbound-dev`     | `unbound`    | `unbound-devel`       | `unbound-devel`     | NO       | DNS resolver    |
| libsodium   | ?             | NO       | `libsodium-dev`      | `libsodium`  | `libsodium-devel`     | `libsodium-devel`   | NO       | cryptography    |
| libunwind   | any           | NO       | `libunwind8-dev`     | `libunwind`  | `libunwind-devel`     | `libunwind-devel`   | YES      | Stack traces    |
| liblzma     | any           | NO       | `liblzma-dev`        | `xz`         | `liblzma-devel`       | `xz-devel`          | YES      | For libunwind   |
| libreadline | 6.3.0         | NO       | `libreadline6-dev`   | `readline`   | `readline-devel`      | `readline-devel`    | YES      | Input editing   |
| expat       | 1.1           | NO       | `libexpat1-dev`      | `expat`      | `expat-devel`         | `expat-devel`       | YES      | XML parsing     |
| GTest       | 1.5           | YES      | `libgtest-dev`[1]    | `gtest`      | `gtest-devel`         | `gtest-devel`       | YES      | Test suite      |
| ccache      | any           | NO       | `ccache`             | `ccache`     | `ccache`              | `ccache`            | YES      | Compil. cache   |
| Doxygen     | any           | NO       | `doxygen`            | `doxygen`    | `doxygen`             | `doxygen`           | YES      | Documentation   |
| Graphviz    | any           | NO       | `graphviz`           | `graphviz`   | `graphviz`            | `graphviz`          | YES      | Documentation   |
| lrelease    | ?             | NO       | `qttools5-dev-tools` | `qt5-tools`  | `qt5-tools`           | `qt5-linguist`      | YES      | Translations    |
| libhidapi   | ?             | NO       | `libhidapi-dev`      | `hidapi`     | `hidapi-devel`        | `hidapi-devel`      | YES      | Hardware wallet |
| libusb      | ?             | NO       | `libusb-1.0-0-dev`   | `libusb`     | `libusb-devel`        | `libusbx-devel`     | YES      | Hardware wallet |
| libprotobuf | ?             | NO       | `libprotobuf-dev`    | `protobuf`   | `protobuf-devel`      | `protobuf-devel`    | YES      | Hardware wallet |
| protoc      | ?             | NO       | `protobuf-compiler`  | `protobuf`   | `protobuf`            | `protobuf-compiler` | YES      | Hardware wallet |
| libudev     | ?             | NO       | `libudev-dev`        | `systemd`    | `eudev-libudev-devel` | `systemd-devel`     | YES      | Hardware wallet |

[1] On Debian/Ubuntu `libgtest-dev` only includes sources and headers. You must
build the library binary manually. This can be done with the following command `sudo apt-get install libgtest-dev && cd /usr/src/gtest && sudo cmake . && sudo make`
then:

* on Debian:
  `sudo mv libg* /usr/lib/`
* on Ubuntu:
  `sudo mv lib/libg* /usr/lib/`

[2] libnorm-dev is needed if your zmq library was built with libnorm, and not needed otherwise

## Install Dependencies

First you'll need to install required dependencies for your operating system.

### Ubuntu/Debian

```bash
sudo apt update && sudo apt install build-essential cmake pkg-config libboost-all-dev libssl-dev libzmq3-dev libpgm-dev libunbound-dev libsodium-dev git
```

### Windows

Install MSYS2 (Software Distribution and Building Platform for Windows):
[MSYS2 Website][msys2-link]

Open MSYS2 Shell and run below to update:
```bash
pacman -Syu
```

You'll need below dependencies to build Nerva.  Run command for your target Windows version.

Windows 64-bit (MSYS2 MINGW64):
```bash
pacman -S mingw-w64-x86_64-toolchain make mingw-w64-x86_64-cmake mingw-w64-x86_64-boost mingw-w64-x86_64-openssl mingw-w64-x86_64-zeromq mingw-w64-x86_64-libsodium mingw-w64-x86_64-hidapi mingw-w64-x86_64-unbound git
```

Windows 32-bit (MSYS2 MINGW32):
```bash
pacman -S mingw-w64-i686-toolchain make mingw-w64-i686-cmake mingw-w64-i686-boost mingw-w64-i686-openssl mingw-w64-i686-zeromq mingw-w64-i686-libsodium mingw-w64-i686-hidapi mingw-w64-i686-unbound git
```

### MacOS

If you do not have it already, install Xcode, command line tools first:
```bash
xcode-select --install
```

You won't be able to do this through SSH as when you run it, you get pop-up box where you need to press Install and agree to license.

Now install Homebrew:
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

After installation, follow instructions to add brew to your PATH.

Once you have brew, you can install dependencies using provided Brewfile located under (note you need to [clone Nerva repository first](#clone-repository) and be in the `nerva` directory):
```bash
brew update && brew bundle --file=contrib/brew/Brewfile
```

## Clone Repository

In Terminal or MSYS2 Shell, go to directory where you want to clone NERVA (ex: `/home/USER_NAME` or `/c/msys64/usr/local`) and clone repository:
```bash
git clone --recursive https://github.com/nerva-project/nerva.git
```

This will create `nerva` directory.

To clone specific branch add `--branch` at the end of git command:
```bash
git clone --recursive https://github.com/nerva-project/nerva.git --branch branch-name
```

If you already have the repository cloned, initialize update:
```bash
cd nerva && git submodule init && git submodule update
```

## Build
Make sure you're in `nerva` directory and start build process:

### Linux

For a normal build:
```bash
make
```

For a static build:
```bash
make release-static
```

If your CPU does not support AES instructions, you can build using:
```bash
make release-noaes
```

The resulting executables can be found in `build/release/bin`.

### Windows

On windows only static builds are possible so build as under (depending on whether you want 32-bit or 64-bit binaries):
```bash
make release-static-win64
```
or
```bash
make release-static-win32
```

The resulting executables can be found in `build/release/bin`

### MacOS

For a normal build:
```bash
make
```

For a static build:
```bash
make release-static
```

If your CPU does not support AES instructions, you can build using:
```bash
make release-noaes
```

The resulting executables can be found in `build/release/bin`.

### Build Options

There are several options that can be given to `make` to control the build process. Below is a list of the most important options:

- `USE_SINGLE_BUILDDIR=1`: By default, the build system uses separate directories for each build type (e.g., `debug`, `release`, etc.). When this option is used, all build types will be built in the same directory. This is useful when the build directory is on a RAM disk or other non-persistent storage.
- `-jN`: This option can be added to the `make` command to build using multiple processes. This can greatly speed up the build process. For example, `make -j2` will use two processes.

## Building portable statically linked binaries

By default, in either dynamically or statically linked builds, binaries target the specific host processor on which the build happens and are not portable to other processors. Portable binaries can be built using the following targets:

* ```make release-static-linux-x86_64``` builds binaries on Linux on x86_64 portable across POSIX systems on x86_64 processors
* ```make release-static-linux-i686``` builds binaries on Linux on x86_64 or i686 portable across POSIX systems on i686 processors
* ```make release-static-linux-armv8``` builds binaries on Linux portable across POSIX systems on armv8 processors
* ```make release-static-linux-armv7``` builds binaries on Linux portable across POSIX systems on armv7 processors
* ```make release-static-linux-armv6``` builds binaries on Linux portable across POSIX systems on armv6 processors
* ```make release-static-mac-x86_64``` builds binaries on macOS on x86_64 portable across macOS systems on x86_64 processors
* ```make release-static-mac-armv8``` builds binaries on macOS on arm64 portable across macOS systems on arm64 processors
* ```make release-static-win64``` builds binaries on 64-bit Windows portable across 64-bit Windows systems
* ```make release-static-win32``` builds binaries on 64-bit or 32-bit Windows portable across 32-bit Windows systems

## Cross Compiling

You can also cross-compile static binaries on Linux for Windows and macOS with the `depends` system.

* ```make depends target=x86_64-linux-gnu``` for 64-bit linux binaries.
* ```make depends target=x86_64-w64-mingw32``` for 64-bit windows binaries.
    * Requires: `python3 g++-mingw-w64-x86-64 wine1.6 bc`
    * You also need to run:  
      ```update-alternatives --set x86_64-w64-mingw32-g++ x86_64-w64-mingw32-g++-posix && update-alternatives --set x86_64-w64-mingw32-gcc x86_64-w64-mingw32-gcc-posix```
* ```make depends target=x86_64-apple-darwin``` for macOS binaries.
    * Requires: `cmake imagemagick libcap-dev librsvg2-bin libz-dev libbz2-dev libtiff-tools python-dev`
* ```make depends target=i686-linux-gnu``` for 32-bit linux binaries.
    * Requires: `g++-multilib bc`
* ```make depends target=i686-w64-mingw32``` for 32-bit windows binaries.
    * Requires: `python3 g++-mingw-w64-i686`
* ```make depends target=arm-linux-gnueabihf``` for armv7 binaries.
    * Requires: `g++-arm-linux-gnueabihf`
* ```make depends target=aarch64-linux-gnu``` for armv8 binaries.
    * Requires: `g++-aarch64-linux-gnu`
* ```make depends target=x86_64-unknown-freebsd``` for freebsd binaries.
    * Requires: `clang-8`
* ```make depends target=arm-linux-android``` for 32bit android binaries
* ```make depends target=aarch64-linux-android``` for 64bit android binaries

The required packages are the names for each toolchain on apt. Depending on your distro, they may have different names. The `depends` system has been tested on Ubuntu 18.04 and 20.04.

Using `depends` might also be easier to compile Monero on Windows than using MSYS. Activate Windows Subsystem for Linux (WSL) with a distro (for example Ubuntu), install the apt build-essentials and follow the `depends` steps as depicted above.

The produced binaries still link libc dynamically. If the binary is compiled on a current distribution, it might not run on an older distribution with an older installation of libc. Passing `-DBACKCOMPAT=ON` to cmake will make sure that the binary will run on systems having at least libc version 2.17.

## Gitian builds

See [contrib/gitian/README.md](../contrib/gitian/README.md).

<!-- Reference links -->
[msys2-link]: https://www.msys2.org
