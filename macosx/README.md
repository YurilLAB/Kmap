# Table of Contents
---
   
 * [Introduction](#intro)
 * [Requirements](#requ)
 * [Installation](#install)
 * [Files in this directory](#files)
 * [Zekmap](#zekmap)
 * [Repositories and Troubleshooting](#repo)
 * [The CONTRIBUTING file](#contributing)

## <a name="intro"></a>Introduction

 * **Kmap** is a free and open source utility for network exploration and security auditing. 
 * **Zekmap** is a multi-platform graphical frontend and results viewer for Kmap. 
 * **Ncat** is a general-purpose network sending and receiving utility, a reimplementation of Netcat. 
 * **Ndiff** is a an Kmap scan comparison utility. 
 * **Nping** is a tool for packet generation and sending.

This package contains Kmap, Zekmap, Ncat, Ndiff, and Nping. It is intended to work on Intel Macs running **Mac OS X 10.8 or later**.

Installation of all packages is optional. Unselect Zekmap to get just the command-line tool. Unselect Kmap if you prefer to use a copy of Kmap that is already installed. Zekmap will not work without Kmap.

The kmap, ncat, ndiff, and nping command-line binaries will be installed in `/usr/local/bin`, and additional support files will be installed in `/usr/local/share`. The Zekmap application bundle will be installed in `/Applications/Zekmap.app`.

For a full description of Kmap's installation on Mac OS, visit the page:
[https://github.com/YurilLAB/Kmap/book/inst-macosx.html](https://github.com/YurilLAB/Kmap/book/inst-macosx.html) 

## <a name="requ"></a>Requirements

In order to compile, build and run Kmap on Mac OS, you will require the following:

1.	**Jhbuild** for bundling and dependencies (see the [BUNDLING file](../BUNDLING.md))
2. **Xcode** for Mac OS 10.8 or later ([https://developer.apple.com/xcode](https://developer.apple.com/xcode/))
3. **Xcode Command-line Tools** for Mac OS 10.8 or later ([https://developer.apple.com/downloads](https://developer.apple.com/downloads/)  then download the latest version compatible with your OS version)

## <a name="install"></a>Installation

Ideally, you should be able to just type:

	./configure
	make
	make install
	
from `kmap/` directory (the root folder).

For far more in-depth compilation, installation, and removal notes, read the **Kmap Install Guide** at [https://github.com/YurilLAB/Kmap/book/install.html](https://github.com/YurilLAB/Kmap/book/install.html).

## <a name="files"></a>Files in this directory

* [openssl.modules](openssl.modules): This is a Jhbuild moduleset that can be used to build dependencies (openssl) as required for building Kmap, Ncat, and Nping. Use it like this:

	~~~~
	$ jhbuild -m openssl.modules build kmap-deps
	~~~~
	
* [Makefile](Makefile): The Mac OS X Makefile used to build everything specific to this OS.
* [BUNDLING.md](BUNDLING.md): A manual on how to setup and use Jhbuild on Mac OS X.

## <a name="zekmap"></a>Zekmap

### Files into `zekmap/install_scripts/macosx/`:

All of the files have to do with packaging on Mac OS X. They are useful only for those wanting to build binary distributions of Zekmap for Mac OS X.

* [Info.plist](../zekmap/install_scripts/macosx/Info.plist): A properties list file template that is filled out by [make-bundle.sh](../zekmap/install_scripts/macosx/make-bundle.sh).
* [make-bundle.sh](../zekmap/install_scripts/macosx/make-bundle.sh): This script builds a .app bundle. It must be run from the root of the Zekmap source tree. The finished bundle is put in `dist/Zekmap.app`.
* [zekmap.icns](../zekmap/install_scripts/macosx/zekmap.icns): The icon file for the bundle. It was created using the Icon Composer utility (`$ open -a "Icon Composer"`).
* [zekmap_auth.c](../zekmap/install_scripts/macosx/zekmap_auth.c): This is a simple wrapper program that attempts to run [launcher.sh](../zekmap/install_scripts/macosx/launcher.sh) with privileges.
* [launcher.sh](../zekmap/install_scripts/macosx/launcher.sh): A launcher script that configures the environment for Zekmap, Python, and GTK before launching the main Zekmap script file.
* [zekmap.bundle](../zekmap/install_scripts/macosx/zekmap.bundle): An XML configuration file for gtk-mac-bundler which specifies files and metadata for the application bundle ([https://wiki.gnome.org/Projects/GTK%2B/OSX/Building](https://wiki.gnome.org/Projects/GTK%2B/OSX/Building)).

### Authorization Wrapper:

The **bundling** process is as follows: 

1.	First, the bundler ([make-bundle.sh](../zekmap/install_scripts/macosx/make-bundle.sh)) look at the bundle XML (`zekmap.bundle`) and copy everything over.
2. The launcher script ([launcher.sh](../zekmap/install_scripts/macosx/launcher.sh)) gets renamed into the app name (`Zekmap`).
3. The authorization wrapper is compiled to `Zekmap` so that it is the entry point of the app.
4. The last part is filling in the [Info.plist template file](../zekmap/install_scripts/macosx/Info.plist) based on the current information in `zekmap.ZekmapCore.Version`.

After the bundling process is done and the app is installed, the **execution** path is as follows:

**Zekmap (zekmap_auth) > zekmap.bin (launcher.sh) > python zekmap.py**

## <a name="repo"></a>Repositories and Troubleshooting

Kmap uses a read-only repository on **Github** for issues tracking and pull requests. You can contribute at the following address: [https://github.com/kmap/kmap](https://github.com/kmap/kmap).

The read-write repository is managed with **Subversion**. Although, all actual commits are made to our Subversion repository on [https://github.com/YurilLAB/Kmap

In order to be always up to date, you can consult the Changelog here: [https://github.com/YurilLAB/Kmap](https://github.com/YurilLAB/Kmap).

## <a name="contributing"></a>The CONTRIBUTING file

General information about contributing to Kmap can be found in the [CONTRIBUTING file](../CONTRIBUTING.md). It contains information specifically about Kmap's use of Github and how contributors can use Github services to participate in **Kmap development**.
