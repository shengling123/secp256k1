all: main
#$^ 代表所有的依赖对象
#$@ 代表目标
#$< 代表第一个依赖对象

OBJS = tinykeccak.o

DEFINE= -DUSE_NUM_NONE -DUSE_FIELD_10X26 -DUSE_FIELD_INV_BUILTIN -D USE_SCALAR_INV_BUILTIN \
	-DUSE_SCALAR_8X32 -DUSE_ENDOMORPHISM -DENABLE_MODULE_ECDH -DENABLE_MODULE_ECDH -DENABLE_MODULE_SCHNORR \
	-DENABLE_MODULE_RECOVERY

main: $(OBJS)
	gcc -w -g $(DEFINE) -o $@ test.c -I. -I.. -I../src -L../.libs -lsecp256k1 $<

tinykeccak.o:
	gcc -w -g -c tinykeccak.c

clean:
	rm -rf main $(OBJS)