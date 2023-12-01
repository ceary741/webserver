
default : httpserver.c httpserver.h
	gcc httpserver.c -lpthread -lssl -lcrypto -o test -Wall -g

