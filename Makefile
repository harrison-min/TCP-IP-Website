# Compiler and flags
CC       := gcc
CFLAGS   := -Wall -D_WIN32_WINNT=0x0601
LDFLAGS  := -lws2_32

# Directories
SRC_DIR  := src
OBJ_DIR  := obj
BIN_DIR  := bin

# Subdirectories (escape spaces for make)
SRV_SUB  := $(SRC_DIR)/TCP_server
CLT_SUB  := $(SRC_DIR)/Test_Client

# Source files
SRV_SRC  := $(SRV_SUB)/server.c
CLT_SRC  := $(CLT_SUB)/client.c

# Object files
SRV_OBJ  := $(OBJ_DIR)/server.o
CLT_OBJ  := $(OBJ_DIR)/client.o

# Binaries
SRV_BIN  := $(BIN_DIR)/server.exe
CLT_BIN  := $(BIN_DIR)/client.exe

.PHONY: all clean

# Default target
all: $(BIN_DIR) $(OBJ_DIR) $(SRV_BIN) $(CLT_BIN)

# Ensure output directories exist
$(BIN_DIR) $(OBJ_DIR):
	mkdir $@

# Compile server.c → obj/server.o
$(SRV_OBJ): $(SRV_SRC)
	$(CC) $(CFLAGS) -c "$(SRV_SRC)" -o "$(SRV_OBJ)"

# Compile client.c → obj/client.o
$(CLT_OBJ): $(CLT_SRC)
	$(CC) $(CFLAGS) -c "$(CLT_SRC)" -o "$(CLT_OBJ)"

# Link obj/server.o → bin/server.exe
$(SRV_BIN): $(SRV_OBJ)
	$(CC) $(CFLAGS) "$(SRV_OBJ)" -o "$(SRV_BIN)" $(LDFLAGS)

# Link obj/client.o → bin/client.exe
$(CLT_BIN): $(CLT_OBJ)
	$(CC) $(CFLAGS) "$(CLT_OBJ)" -o "$(CLT_BIN)" $(LDFLAGS)

# Remove all generated files
clean:
	-del /Q $(OBJ_DIR)\*.o $(BIN_DIR)\*.exe 2>nul || rm -f $(OBJ_DIR)/*.o $(BIN_DIR)/*.exe
