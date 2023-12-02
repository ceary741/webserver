
default : httpserver.c httpserver.h
	gcc httpserver.c -lpthread -lssl -lcrypto -o test -Wall -g -L/opt/homebrew/opt/openssl/lib -I/opt/homebrew/opt/openssl/include

