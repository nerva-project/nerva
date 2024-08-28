# NERVA

Copyright (c) 2021 The NERVA Project.   
Copyright (c) 2014-2021 The Monero Project.   
Copyright (c) 2017-2018 The Masari Project.   
Portions Copyright (c) 2012-2013 The Cryptonote developers.



## License 

See [LICENSE](LICENSE). 



## Compiling Nerva from source 
Nerva can be compiled by running build script inside `nerva/builder/` 

By default, it checks if your processor has AES support and builds based on that.  It calls default() function.  There is also release() function that creates both AES and non-AES files.  If you'd like to use that, call it at the end of build script instead of default function. 

In the same build directory, there is also environment script file that controls some aspects of the build.  By default, it will build in Release mode and will not build extras.  You can change that behavior by editing those flags so to build extras, change the flag from OFF to ON: `BUILD_EXTRAS=ON`. 

If you run default build, files are created under: `nerva/build/output/windows/release/bin/` 

If you run production build, files are created under: `nerva/build/output/`. Those files are automatically zipped so you need zip: 
Linux: `sudo apt install zip` 
Windows: `pacman -S zip` 

Inside `nerva/builder/environment`, there is THREAD_COUNT variable that's set to 8.  You can increase or decrease it based on your system.  If you're building on low end system and seeing errors, change it to 1 or something lower than 8. 



## Compiling on Linux 

### Install NERVA dependencies on Debian/Ubuntu 
```bash
sudo apt update && sudo apt install build-essential cmake pkg-config libboost-all-dev libssl-dev libzmq3-dev libpgm-dev libunbound-dev libsodium-dev git
```

### Clone NERVA repository 
```bash
git clone --recursive https://github.com/nerva-project/nerva.git
```
This will create `nerva` directory. 

To clone specific branch add `--branch` at the end of git command: 
```bash
git clone --recursive https://github.com/nerva-project/nerva.git --branch your-branch-name
```

### Build on Linux 
Go to builder directory and start build process: 
```bash
cd nerva/builder
```
```bash
sudo ./build
```



## Compiling on Windows 

### Install MSYS2 
Install MSYS2 (Software Distribution and Building Platform for Windows): 
[MSYS2 Website][msys2-link]

Open MSYS2 Shell and run below to update: 
```bash
pacman -Syu
```

### Install NERVA dependancies 
You'll need below dependencies to build nerva.  Run command for your target Windows version. 
Windows 64-bit:
```bash
pacman -S mingw-w64-x86_64-toolchain make mingw-w64-x86_64-cmake mingw-w64-x86_64-boost mingw-w64-x86_64-openssl mingw-w64-x86_64-zeromq mingw-w64-x86_64-libsodium mingw-w64-x86_64-hidapi mingw-w64-x86_64-unbound mingw-w64-x86_64-cppzmq git
```

Windows 32-bit: 
```bash
pacman -S mingw-w64-i686-toolchain make mingw-w64-i686-cmake mingw-w64-i686-boost mingw-w64-i686-openssl mingw-w64-i686-zeromq mingw-w64-i686-libsodium mingw-w64-i686-hidapi mingw-w64-i686-unbound mingw-w64-i686-cppzmq git
```

### Clone NERVA repository 
In MSYS2 shell, go to directory where you want to clone nerva (ex: `/c/msys64/usr/local`) and clone repository: 
```bash
git clone --recursive https://github.com/nerva-project/nerva.git
```
This will create `nerva` directory. 

To clone specific branch add `--branch` at the end of git command: 
```bash
git clone --recursive https://github.com/nerva-project/nerva.git --branch your-branch-name
```

### Build on Windows 
Go to builder directory and start build process: 
```bash
cd nerva/builder
```
```bash
./build
```



## Compiling on macOS 

### Install Homebrew 
Install Xcode, command line tools first: 
```bash
xcode-select --install
```
You won't be able to do this through SSH as when you run it, you get pop-up box where you need to press Install and agree to license. 

Now install Homebrew: 
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```
After installation, follow instructions to add brew to your PATH. 

### Clone NERVA repository 
```bash
sudo git clone --recursive https://github.com/nerva-project/nerva.git
```
This will create `nerva` directory. 

To clone specific branch add `--branch` at the end of git command: 
```bash
sudo git clone --recursive https://github.com/nerva-project/nerva.git --branch your-branch-name
```

### Install NERVA dependencies 
Install all macOS dependencies using Brewfile located under: 
`nerva\contrib\brew\Brewfile` 

```bash
brew update && brew bundle --file=contrib/brew/Brewfile
```

### Build on macOS 
Go to builder directory and start build process: 
```bash
cd nerva/builder
```
```bash
sudo ./build
```



## Help Me! 

[GitHub docs][nerva-docs-link] is your friend, or head to [Discord][nerva-discord-link] to talk to a person. 



<!-- Reference links -->
[nerva-discord-link]: https://discord.gg/jsdbEns
[nerva-docs-link]: https://docs.nerva.one
[msys2-link]: https://www.msys2.org
