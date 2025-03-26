INC_DIR	= ./include
SRC_DIR = ./src
OBJ_DIR	= ./object

SRC_FILES = $(wildcard $(SRC_DIR)/*.cpp)
OBJ_FILES = $(SRC_FILES:.cpp=.o)
OBJ_PATH  = $(patsubst $(SRC_DIR)/%,$(OBJ_DIR)/%,$(OBJ_FILES))

LIBS	= 
CC	= /usr/bin/g++
CFLAGS	= -g -I$(INC_DIR) -std=c++11

all: assignment1

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CC) -c -o $@ $< $(CFLAGS)

assignment1: $(OBJ_PATH)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f $(OBJ_DIR)/*.o $(INC_DIR)/*~ assignment1 ./logs/*
