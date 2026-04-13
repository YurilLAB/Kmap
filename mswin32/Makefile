export MSYS2_ARG_CONV_EXCL=*
MAKENSIS=C:/Program Files (x86)/NSIS/makensis.exe
SIGNTOOL := $(shell powershell.exe -NoProfile -WindowStyle Hidden -NonInteractive -Command '$$vs=Get-VSSetupInstance -All | Select-VSSetupInstance -Latest; $$vsp=$$vs.InstallationPath; & "$$env:comspec" /c "`"$$vsp\\VC\\Auxiliary\\Build\\vcvarsall.bat`" x86 & where signtool"' | tail -n 1)
KMAPDIR=..
KMAPDIR_WIN=$(shell echo '$(KMAPDIR)' | sed 's|/cygdrive/\(.\)|\1:|;s|/|\\|g')
ZEKMAP_WINDIR=$(KMAPDIR)/zekmap/install_scripts/windows

include make-vars.make
export NPCAP_VERSION := $(shell ls npcap-*.exe | sed -e 's/npcap-\([0-9.]*\)[-oem]*\.exe/\1/' -e 'q')

NSE_FILES = $(KMAPDIR)/scripts/script.db $(KMAPDIR)/scripts/*.nse
KMAP_MSWIN32_AUX = $(KMAPDIR)/../kmap-mswin32-aux
SIGNTOOL_ARGS = sign /a /n "Kmap Software LLC" /tr http://timestamp.digicert.com /td sha256 /fd sha256
NSIS_COMMON_ARGS = "/DVERSION=$(KMAP_VERSION)" "/DNUM_VERSION=$(KMAP_NUM_VERSION)" "/DNPCAP_VERSION=$(NPCAP_VERSION)"
NSIS_OEM_ARGS = "/DKMAP_NAME=$(KMAP_OEM_NAME)" "/DKMAP_OEM=1"
NSIS_STD_ARGS = "/DKMAP_NAME=$(KMAP_NAME)"
ifdef OEM_SUFFIX
NSIS_ARGS = $(NSIS_COMMON_ARGS) $(NSIS_OEM_ARGS)
else
NSIS_ARGS = $(NSIS_COMMON_ARGS) $(NSIS_STD_ARGS)
endif


PLATFORM=Win32
VCCONFIG=Release

all: build-kmap

check:
	test -n "$(KMAP_NAME)"
	test -n "$(KMAP_OEM_NAME)"
	test -n "$(KMAP_VERSION)"
	test -n "$(KMAP_NUM_VERSION)"

make-vars.make: make-vars.h
	cmd /c Build.bat Vars

bundle-kmap: bundle-zip bundle-nsis

build-kmap${OEM_SUFFIX}: kmap.sln
	cmd /c Build.bat Build "$(VCCONFIG)${OEM_SUFFIX}"

vc_redist.x86.exe:
	wget https://aka.ms/vs/17/release/vc_redist.x86.exe

stage-common: $(KMAPDIR)/CHANGELOG $(KMAPDIR)/LICENSE $(KMAPDIR)/kmap-mac-prefixes $(KMAPDIR)/kmap-os-db $(KMAPDIR)/kmap-protocols $(KMAPDIR)/kmap-rpc $(KMAPDIR)/kmap-service-probes $(KMAPDIR)/kmap-services $(KMAPDIR)/docs/kmap.xsl $(KMAPDIR)/nse_main.lua $(KMAPDIR)/mswin32/kmap_performance.reg $(KMAPDIR)/README-WIN32 $(KMAPDIR)/docs/3rd-party-licenses.txt icon1.ico LICENSE.formatted vc_redist.x86.exe
	mkdir -p kmap-$(KMAP_VERSION)
	cp $^ kmap-$(KMAP_VERSION)/
# Use "cmd /c copy" rather than "cp" to preserve Windows ACLs. Using
# "cp" means that the copied DLLs don't have the same ACL and cause an
# error on startup: 0xc0000022.
	cmd /c copy $(subst /,\\,$(KMAP_MSWIN32_AUX))\\OpenSSL\\bin\\*.dll kmap-$(KMAP_VERSION)
	cmd /c copy $(KMAPDIR_WIN)\\libssh2\\win32\\$(VCCONFIG)_dll\\libssh2.dll kmap-$(KMAP_VERSION)
	cmd /c copy $(KMAPDIR_WIN)\\libz\\contrib\\vstudio\\vc16\\x86\\ZlibDll$(VCCONFIG)WithoutAsm\\zlibwapi.dll kmap-$(KMAP_VERSION)
	mkdir -p kmap-$(KMAP_VERSION)/scripts
	cp -f $(NSE_FILES) kmap-$(KMAP_VERSION)/scripts/
	for f in `cd $(KMAPDIR) && find nselib -name .svn -prune -o -type d -print`; do \
		mkdir -p kmap-$(KMAP_VERSION)/$$f; \
	done
	for f in `cd $(KMAPDIR) && find nselib -name .svn -prune -o -type f -print`; do \
		cp -f $(KMAPDIR)/$$f kmap-$(KMAP_VERSION)/$$f; \
	done
	cp -r $(KMAPDIR)/docs/licenses kmap-$(KMAP_VERSION)/
	rm -rf kmap-$(KMAP_VERSION)/licenses/.svn
	cp $(KMAPDIR)/ncat/$(VCCONFIG)/ncat.exe kmap-$(KMAP_VERSION)
	cp $(KMAPDIR)/ncat/$(VCCONFIG)/ca-bundle.crt kmap-$(KMAP_VERSION)
	cp $(KMAPDIR)/nping/$(VCCONFIG)/nping.exe kmap-$(KMAP_VERSION)
# Install the ndiff batch file wrapper in the zip distribution.
	cp $(KMAPDIR)/ndiff/ndiff.py kmap-$(KMAP_VERSION)/ndiff.py
	cp python-wrap.bat kmap-$(KMAP_VERSION)/ndiff.bat
	$(MAKE) -C $(ZEKMAP_WINDIR)
	rm -rf kmap-$(KMAP_VERSION)/zekmap
	cp -R $(ZEKMAP_WINDIR)/dist/zekmap-w64/mingw64 kmap-$(KMAP_VERSION)/zekmap
	cp $(KMAPDIR)/zekmap/README kmap-$(KMAP_VERSION)/ZEKMAP_README
	cp $(KMAPDIR)/zekmap/COPYING_HIGWIDGETS kmap-$(KMAP_VERSION)
	cp $(KMAPDIR)/ndiff/README kmap-$(KMAP_VERSION)/NDIFF_README

stage: stage-kmap stage-kmap-oem stage-common

stage-kmap:
	$(MAKE)	OEM_SUFFIX= stage-kmap-main

stage-kmap-oem:
	$(MAKE)	OEM_SUFFIX=-oem stage-kmap-main

kmap-$(KMAP_VERSION)${OEM_SUFFIX}/Uninstall.exe: nsis/Kmap.nsi LICENSE.formatted
	mkdir -p kmap-$(KMAP_VERSION)${OEM_SUFFIX}
	"$(MAKENSIS)" /DINNER $(NSIS_ARGS) nsis/Kmap.nsi
	kmap-$(KMAP_VERSION)${OEM_SUFFIX}/tempinstaller.exe || test $$? -eq 2
	rm kmap-$(KMAP_VERSION)${OEM_SUFFIX}/tempinstaller.exe

stage-kmap-main: build-kmap${OEM_SUFFIX} kmap-$(KMAP_VERSION)${OEM_SUFFIX}/Uninstall.exe
	cp $(VCCONFIG)${OEM_SUFFIX}/kmap.exe kmap-$(KMAP_VERSION)${OEM_SUFFIX}/

sign-files: kmap-$(KMAP_VERSION)-oem/kmap.exe kmap-$(KMAP_VERSION)/kmap.exe kmap-$(KMAP_VERSION)-oem/Uninstall.exe kmap-$(KMAP_VERSION)/Uninstall.exe kmap-$(KMAP_VERSION)/ncat.exe kmap-$(KMAP_VERSION)/nping.exe kmap-$(KMAP_VERSION)/libssh2.dll kmap-$(KMAP_VERSION)/libcrypto-3.dll kmap-$(KMAP_VERSION)/libssl-3.dll kmap-$(KMAP_VERSION)/zlibwapi.dll
	# TODO: evaluate whether we should also sign the Python stuff for Zekmap, Ndiff
	"$(SIGNTOOL)" $(SIGNTOOL_ARGS) $^ kmap-$(KMAP_VERSION)/zekmap/bin/* kmap-$(KMAP_VERSION)/zekmap/lib/gdk-pixbuf-2.0/*/loaders/*.dll
	touch sign-files

bundle-nsis: sign-files
	"$(MAKENSIS)" $(NSIS_COMMON_ARGS) $(NSIS_STD_ARGS) nsis/Kmap.nsi
	"$(MAKENSIS)" $(NSIS_COMMON_ARGS) $(NSIS_OEM_ARGS) nsis/Kmap.nsi
	"$(SIGNTOOL)" $(SIGNTOOL_ARGS) kmap-$(KMAP_VERSION)-setup.exe kmap-$(KMAP_VERSION)-oem-setup.exe

bundle-zip: bundle-zip-oem

bundle-zip-public:
	$(MAKE) OEM_SUFFIX= bundle-zip-main

bundle-zip-oem:
	$(MAKE) OEM_SUFFIX=-oem bundle-zip-main

bundle-zip-main: sign-files
	rm -f kmap-$(KMAP_VERSION)${OEM_SUFFIX}-win32.zip
	test -n "${OEM_SUFFIX}" \
	       && cp -n -R kmap-$(KMAP_VERSION)/* kmap-$(KMAP_VERSION)${OEM_SUFFIX}/ \
	       || true
	cp npcap-$(NPCAP_VERSION)${OEM_SUFFIX}.exe kmap-$(KMAP_VERSION)${OEM_SUFFIX}
	zip -x kmap-$(KMAP_VERSION)${OEM_SUFFIX}/ZEKMAP_README \
	  kmap-$(KMAP_VERSION)${OEM_SUFFIX}/zekmap/\* \
	  kmap-$(KMAP_VERSION)${OEM_SUFFIX}/COPYING_HIGWIDGETS \
	  kmap-$(KMAP_VERSION)${OEM_SUFFIX}/Uninstall.exe \
	  kmap-$(KMAP_VERSION)${OEM_SUFFIX}/icon1.ico \
	  -r kmap-$(KMAP_VERSION)${OEM_SUFFIX}-win32.zip kmap-$(KMAP_VERSION)${OEM_SUFFIX}
	rm kmap-$(KMAP_VERSION)${OEM_SUFFIX}/npcap-$(NPCAP_VERSION)${OEM_SUFFIX}.exe

LICENSE.formatted: $(KMAPDIR)/LICENSE
	./license-format/licformat.sh "$<" > "$@"

clean:
	cmd /c Build.bat Clean "$(VCCONFIG)${OEM_SUFFIX}"
	$(MAKE) -C $(ZEKMAP_WINDIR) clean
	rm -rf make-vars.make kmap-$(KMAP_VERSION) kmap-$(KMAP_VERSION)-oem Debug Release Release-oem msbuild.log LICENSE.formatted
