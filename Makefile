CC = cc
CFLAGS  = -g
INCLUDES = -I/usr/local/include -L/usr/local/lib
COMPILE  = $(CC) $(CFLAGS) $(INCLUDES)

all:	dns-server-frag

dns-server-frag:	dns-server-frag.c
	$(COMPILE) -o dns-server-frag dns-server-frag.c
