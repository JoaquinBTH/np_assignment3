CC = gcc
CC_FLAGS = -w -g



all: test client server


main.o: main.c
	$(CC) -Wall -I. -c main.c

client.o: client.c
	$(CC) -Wall -I. -c client.c

server.o: server.c
	$(CC) -Wall -I. -c server.c

test: main.o
	$(CC) -I./ -Wall -lncurses -o test main.o 


client: client.o
	$(CC) -Wall -pthread -o cchat client.o -lncurses

server: server.o
	$(CC) -Wall -pthread -o cserverd server.o


clean:
	rm *.o test cserverd cchat