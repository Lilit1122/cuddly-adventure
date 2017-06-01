CC=gcc
CFLAGS=-I=/usr/local/include
LIBS=-lnetfilter_queue -lcjson -lm
DEPS=parser1.h
TARGET=nfq
SOURCES= nfq211.c parser1.c
OBJECTS=$(SOURCES:.c=.o)

$(TARGET): $(OBJECTS)
		$(CC) $^ $(LIBS) $(CFLAGS) -o $@ 
%.o: %.c $(DEPS)
		gcc -c $< -o $@ 

