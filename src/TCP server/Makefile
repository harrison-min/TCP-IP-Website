# Compiler and flags
CC = gcc
CFLAGS = -Wall -D_WIN32_WINNT=0x0601
LDFLAGS = -lws2_32

# Target executable
TARGET = server

# Source file
SRC = server.c

# Default rule
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)
