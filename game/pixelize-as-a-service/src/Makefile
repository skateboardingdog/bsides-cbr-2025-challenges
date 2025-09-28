CC = gcc
CFLAGS = -g -Wall -Wextra -O0 -fno-stack-protector -fno-pie -no-pie -z execstack
LDFLAGS = -lpng -lz -lm
TARGET = pixelize
SOURCE = pixelize.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean install uninstall
