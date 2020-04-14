IDIR	= ../include
CC	= gcc
CFLAGS	= -I$(IDIR)

ODIR	= obj
LDIR	= ../lib

LIBS	= -lpcap

_DEPS	= packet_reader.h sniffer.h
DEPS	= $(patsubst %, $(IDIR)/%,$(_DEPS))

_OBJ	= main.o packet_reader.o sniffer.o
OBJ		= $(patsubst %, $(ODIR)/%,$(_OBJ))

$(ODIR)/%.o:	%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

main:	$(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)
