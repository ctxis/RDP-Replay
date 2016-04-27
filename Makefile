all: reply/rdp_replay

libfree_rdp/Makefile:
	cd libfree_rdp && cmake -DCMAKE_BUILD_TYPE=Debug -DWITH_SSE2=ON .

reply/rdp_replay: libfree_rdp/Makefile
	cd libfree_rdp && make
	cd replay && make

clean:
	cd libfree_rdp && make clean
	cd replay && make clean
