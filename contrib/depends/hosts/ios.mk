# iOS host: macOS runner's own Xcode (clang + SDK via xcrun, system cctools).
# Device and simulator share this file; the SDK + target triple switch on the
# host (aarch64-apple-ios vs aarch64-apple-iossimulator). nothing built from source.
IOS_MIN_VERSION=12.0
ifeq ($(findstring simulator,$(full_host_os)),simulator)
  IOS_SDK=iphonesimulator
  CC_target=arm64-apple-ios$(IOS_MIN_VERSION)-simulator
else
  IOS_SDK=iphoneos
  CC_target=arm64-apple-ios$(IOS_MIN_VERSION)
endif
IOS_SDK_PATH=$(shell xcrun --sdk $(IOS_SDK) --show-sdk-path)

ios_CC=clang -target $(CC_target) -isysroot $(IOS_SDK_PATH)
ios_CXX=clang++ -target $(CC_target) -isysroot $(IOS_SDK_PATH) -stdlib=libc++

ios_CFLAGS=-pipe
ios_CXXFLAGS=$(ios_CFLAGS)
ios_ARFLAGS=cr

ios_release_CFLAGS=-O2
ios_release_CXXFLAGS=$(ios_release_CFLAGS)

ios_debug_CFLAGS=-g -O0
ios_debug_CXXFLAGS=$(ios_debug_CFLAGS)

ios_native_toolchain=

ios_cmake_system=iOS

# system ar/ranlib/strip (mac has no aarch64-apple-ios prefixed tools)
ios_AR=ar
ios_RANLIB=ranlib
ios_STRIP=strip
ios_LIBTOOL=libtool
