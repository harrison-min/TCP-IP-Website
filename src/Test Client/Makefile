# Compiler and flags
CC = gcc
CFLAGS = -Wall -D_WIN32_WINNT=0x0601
LDFLAGS = -lws2_32

# Target executable
TARGET = client

# Source file
SRC = client.c

# Default rule
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)
