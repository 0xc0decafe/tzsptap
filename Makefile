CC=cc
LD=$(CC)
LDFLAGS=-Wall
OBJS=tzsptap.o

.PHONY: all
all: tzsptap

tzsptap: $(OBJS)
	$(LD) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm tzsptap *.o
