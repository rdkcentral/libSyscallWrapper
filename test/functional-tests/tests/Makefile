CC = gcc
CFLAGS = -I../../../source -Wall -Wextra -O2
LDFLAGS = ../../../source/.libs/libsecure_wrapper.a -lpthread -lrdkloggers

TARGET = syswrapper_l2_helper
SRC = syswrapper_l2_helper.c

all: $(TARGET)

$(TARGET): $(SRC)
        $(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

clean:
        rm -f $(TARGET) *.o
