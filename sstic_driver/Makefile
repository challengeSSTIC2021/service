obj-m += sstic.o
MODULES_DIR=linux
old:
	make -C $(MODULES_DIR) M=$(PWD) modules
	strip --strip-debug sstic.ko
	cp sstic.ko fs/lib/modules/
	#TODO REMOVE THAT FOR PROD
	gcc -static -o user_test -Wall user_test.c
	cp user_test fs
	gcc -static -o exploit -Wall exploit.c
	cp exploit fs
	gcc -c -Wall -Werror -shared -static -fpic sstic_lib.c -o sstic_lib.so 
	cp sstic_lib.so fs/usr/lib/sstic_lib.so
	cp server.py fs/home/sstic
	#gcc -static -o service -Wall service.c
	#strip --strip-debug service
	#cp service fs/home/congominer
	#cp debugdev.ko fs/lib/modules

rootfs_test: exploit sstic.ko user_test service
	cp exploit fs
	cp user_test fs
	cp service fs/home/sstic/service
	cp sstic.ko fs/lib/modules/
	cd fs && find . |cpio -H newc -o | gzip > ../rootfs.img


rootfs:  sstic.ko  service
	cp service fs/home/sstic/service
	cp sstic.ko fs/lib/modules/
	cd fs && find . |cpio -H newc -o | gzip > ../rootfs.img

clean:
	 make -C $(MODULES_DIR) M=$(PWD) clean
	 rm service
	 rm sstic.ko
	 rm user_test
	 rm exploit

clean_rootfs:
	rm fs/user_test
	rm fs/exploit
	rm fs/home/sstic/service
	rm fs/lib/modules/sstic.ko
	rm rootfs.img

service: service.c sstic_lib.h sstic_lib.c
	gcc -static -o service -Wall sstic_lib.c service.c 

sstic.ko: sstic.c sstic.h
	git submodule update --init linux
	cp linux_config linux/.config
	cd linux && make modules_prepare; cd ..
	make -C $(MODULES_DIR) M=$(PWD) modules
	#strip sstic.ko

user_test: user_test.c sstic_lib.h sstic_lib.c
	gcc -static -o user_test -Wall sstic_lib.c user_test.c 

exploit: exploit.c 
	gcc -static -o exploit -Wall exploit.c 

.PHONY: docker
docker: 
	cp bzImage docker
	cp rootfs.img docker
	cp wrapper.py docker
	cp run_service.sh docker
	git submodule update --init docker/qemu
	#no fucking idea why it can't pull submodule from the docker
	#we do the configure here just for pulling only submodules we need
	
	# Do not configure qemu outside of the docker (get some error when build)
	#cd docker/qemu &&  ./configure --target-list=x86_64-softmmu

