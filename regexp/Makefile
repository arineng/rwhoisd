# Generated automatically from Makefile.in by configure.

# programs
CC     = gcc
AR     = ar
RANLIB = ranlib

# options
LOCAL_INC = -I.
LOCAL_LIBS = 
LOCAL_OPTIONS = 

CFLAGS  = -g -O $(LOCAL_INC) $(LOCAL_OPTIONS) -DHAVE_CONFIG_H
LDFLAGS = 

LIBS    = $(LOCAL_LIBS) -lsocket -lresolv -lnsl 


OBJS = \
        regerror.o \
        regexp.o \
        regsub.o


all: libregexp.a

libregexp.a:$(OBJS)
	$(AR) cru libregexp.a $(OBJS)
	$(RANLIB) libregexp.a

.c.o:
	$(CC) -c $(CFLAGS) $*.c

clean:
	rm -f *.[oa]

distclean: clean
	rm -f Makefile
