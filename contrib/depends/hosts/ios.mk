# iOS (arm64-apple-ios) host: use the macOS runner's own Xcode (clang + iphoneos
# SDK via xcrun, system cctools). nothing built from source here.
IOS_MIN_VERSION=12.0
IOS_SDK_PATH=$(shell xcrun --sdk iphoneos --show-sdk-path)

CC_target=arm64-apple-ios

ios_CC=clang -target $(CC_target) -miphoneos-version-min=$(IOS_MIN_VERSION) -isysroot $(IOS_SDK_PATH)
ios_CXX=clang++ -target $(CC_target) -miphoneos-version-min=$(IOS_MIN_VERSION) -isysroot $(IOS_SDK_PATH) -stdlib=libc++

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
