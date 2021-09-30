CC = g++
CFLAGS = -Wall -Wextra -std=c++17
FILES = datespoofer.cpp
FILENAME = datespoofer.exe

all:
	$(CC) $(CFLAGS) $(FILES) -o $(FILENAME)

clean:
	rm $(FILENAME) -f