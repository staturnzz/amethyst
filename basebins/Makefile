all:
	$(MAKE) -C jbutil all
	$(MAKE) -C launchd_hook all
	$(MAKE) -C base_hook all
	$(MAKE) -C libjailbreak all

clean:
	$(MAKE) -C jbutil clean
	$(MAKE) -C launchd_hook clean
	$(MAKE) -C base_hook clean
	$(MAKE) -C libjailbreak clean

	@rm -rf ./staging_tnsv2
	@rm -rf ./staging_tnsv2_stub
	@rm -rf ./staging
	@rm -rf ./basebins.tar
	@rm -rf ./tnsv2_updater.deb
	@rm -rf ./tnsv2_updater_stub.deb

tnsv2:
	@mkdir -p ./staging_tnsv2/DEBIAN
	@mkdir -p ./staging_tnsv2_stub/DEBIAN
	@umask u=rwx,g=rx,o=rx && mkdir -p ./staging_tnsv2/amethyst/update

	@cp -a ./resources/control ./staging_tnsv2/DEBIAN/control
	@cp -a ./resources/control ./staging_tnsv2_stub/DEBIAN/control
	@cp -a ./resources/postinst ./staging_tnsv2/DEBIAN/postinst

	@cp -a ./jbutil/jbutil ./staging_tnsv2/amethyst/update/jbutil
	@cp -a ./launchd_hook/launchd_hook.dylib ./staging_tnsv2/amethyst/update/launchd_hook.dylib
	@cp -a ./base_hook/base_hook.dylib ./staging_tnsv2/amethyst/update/base_hook.dylib
	@cp -a ./libjailbreak/libjailbreak.dylib ./staging_tnsv2/amethyst/update/libjailbreak.dylib
	
	@chmod 0755 ./staging_tnsv2/amethyst/update/jbutil
	@chmod 0755 ./staging_tnsv2/amethyst/update/launchd_hook.dylib
	@chmod 0755 ./staging_tnsv2/amethyst/update/base_hook.dylib
	@chmod 0755 ./staging_tnsv2/amethyst/update/libjailbreak.dylib
	@chmod 0755 ./staging_tnsv2/DEBIAN/postinst

	@cd ./staging_tnsv2 && find . -name '.DS_Store' -type f -delete
	@cd ./staging_tnsv2_stub && find . -name '.DS_Store' -type f -delete
	COPYFILE_DISABLE=1 dpkg-deb -Znone --root-owner-group --build ./staging_tnsv2 ./tnsv2_updater.deb
	COPYFILE_DISABLE=1 dpkg-deb -Znone --root-owner-group --build ./staging_tnsv2_stub ./tnsv2_updater_stub.deb

package: clean all tnsv2
	@mkdir -p ./staging
	@umask u=rwx,g=rx,o=rx && mkdir -p ./staging/amethyst
	@umask u=rwx,g=rx,o=rx && mkdir -p ./staging/usr/lib

	@cp -a ./jbutil/jbutil ./staging/amethyst/jbutil
	@cp -a ./launchd_hook/launchd_hook.dylib ./staging/amethyst/launchd_hook.dylib
	@cp -a ./base_hook/base_hook.dylib ./staging/usr/lib/base_hook.dylib
	@cp -a ./libjailbreak/libjailbreak.dylib ./staging/usr/lib/libjailbreak.dylib

	@chmod 0755 ./staging/amethyst/jbutil
	@chmod 0755 ./staging/amethyst/launchd_hook.dylib
	@chmod 0755 ./staging/usr/lib/base_hook.dylib
	@chmod 0755 ./staging/usr/lib/libjailbreak.dylib

	@find ./staging -name '.DS_Store' -type f -delete
	cd ./staging && COPYFILE_DISABLE=1 tar --numeric-owner -c --no-xattrs -f ../basebins.tar ./*
