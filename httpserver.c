#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "httpserver.h"

char const *ReqMethod[] = 
{
	[GET]	"GET",
	[POST]	"POST",
	[HEAD]	"HEAD",
	NULL
};

int deny_http = 1;

int main(void)
{
	pthread_t pid_http, pid_https;
	if(pthread_create(&pid_http, NULL, httpServer, NULL) != 0) {
		perror("pthread_create()");
		exit(-1);
	}
	if(pthread_create(&pid_https, NULL, httpsServer, NULL) != 0) {
		perror("pthread_create()");
		exit(-1);
	}

	while(1)
		pause();
	return 0;
}

int https(SSL *ssl)
{
	Mesg *mesg = malloc(sizeof(Mesg));
	mesg->para[0] = NULL;

	if(httpsRead(ssl, mesg) < 0)
	{
		fprintf(stderr, "There is a error request\n");
		freeMesg(mesg);
		return -1;
	}

	if(httpsSend(ssl, mesg) < 0)
	{
		fprintf(stderr, "There is an error when send\n");
		freeMesg(mesg);
		return -1;
	}
	freeMesg(mesg);
	return 0;
}

void freeMesg(Mesg *mesg)
{
	int i;
	for(i = 0; i < PARANUM; i++)
	{
		if(mesg->para[i] == NULL)
			break;
		free(mesg->para[i]);
	}
	free(mesg);

	return;
}

int httpsRead(SSL *ssl, Mesg *mesg)
{
	char buf[BUFSIZE];
	int bytes;

	if(SSL_accept(ssl) < 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	showCerts(ssl);
	bytes = SSL_read(ssl, buf, sizeof(buf));
	if(bytes == BUFSIZE) {
		fprintf(stderr, "GET is too long!\n");
		return -1;
	}
	buf[bytes] = '\0';
	strcpy(mesg->path, ROOTPATH);

	char *line = malloc(BUFSIZE);
	char *line_start = buf;
	char *line_end = buf;
	int cnt = 0;
	while(1)
	{
		line_end = index(line_start, '\n');
		strncpy(line, line_start, line_end-line_start+1);
		line[line_end-line_start+1] = '\0';
		fputs(line, stdout);
		if(strcmp(line, "\r\n") == 0)
			break;

		if(cnt == 0)
		{
			readFirstLine(mesg, line);
		}

		line_start = line_end + 1;
		cnt++;
	}

	free(line);

	if(mesg -> statu != GET)  //only support get method
	{
		mesg -> statu = UNKNOW;
	}
	return 0;
}

int httpsSend(SSL *ssl, const Mesg *mesg)
{
	if(mesg -> statu == UNKNOW)
	{
		char *ret = "HTTP/1.1 404 NOT FOUND\r\nContent-Type: text/html\r\n\r\n <h1>NO THIS METHOD! </h1>"; 
		SSL_write(ssl, ret, strlen(ret)*sizeof(char));
		return -1;
	}
	const char *path = mesg -> path;
	int file = open(path, O_RDONLY);
	if(file < 0)
	{
		if(errno == ENOENT)
		{
			char *ret = "HTTP/1.1 404 NOT FOUND\r\nContent-Type: text/html\r\n\r\n <h1>404 NOT FOUND! </h1>"; 
			SSL_write(ssl, ret, strlen(ret)*sizeof(char));
			return -1;
		} else {
			perror("open()");
			return -1;
		}
	}

	struct stat file_stat;
	fstat(file, &file_stat);
	if(!S_ISREG(file_stat.st_mode))
	{
		char *ret = "HTTP/1.1 404 NOT FOUND\r\nContent-Type: text/html\r\n\r\n <h1>404 NOT FOUND! </h1>"; 
		SSL_write(ssl, ret, strlen(ret)*sizeof(char));
		close(file);
		return -1;
	}

	char* ret = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n";
	SSL_write(ssl, ret, strlen(ret)*sizeof(char));

	char buf[1024];
	while(1)
	{
		int nread;
		nread = read(file, buf, 1024);
		if(nread < 0)
		{
			perror("read()");
			close(file);
			break;
		}
		if(nread == 0)
		{
			close(file);
			break;
		}
		SSL_write(ssl, buf, nread);
	}
	
	return 0;
}

int http(int sd)
{
	Mesg *mesg = malloc(sizeof(Mesg));
	mesg->para[0] = NULL;

	if(httpRead(sd, mesg) < 0)
	{
		fprintf(stderr, "There is a error request in http\n");
		freeMesg(mesg);
		return -1;
	}

	if(httpSend(sd, mesg) < 0)
	{
		fprintf(stderr, "There is an error when send\n");
		freeMesg(mesg);
		return -1;
	}
	freeMesg(mesg);
	return 0;
}

int httpRead(int sd, Mesg *mesg)
{
	FILE *recv;
	int recvfd = dup(sd);
	recv = fdopen(recvfd, "r");
	
	char *line;
	size_t len = 0;
	ssize_t nread;
	strcpy(mesg->path, ROOTPATH);

	int cnt = 0;
	while(1)
	{
		nread = getline(&line, &len, recv);
		if(nread < 0)
		{
			fclose(recv);
			free(line);
			perror("getlien()");
			return -1;
		}
		fputs(line, stdout);
		if(strcmp(line, "\r\n") == 0)
			break;

		if(cnt == 0)
		{
			readFirstLine(mesg, line);
		}
		cnt++;
	}
	fclose(recv);
	free(line);

	if(mesg -> statu != GET)  //only support get method
		mesg -> statu = UNKNOW;
	return 0;
}

int httpSend(int sd, const Mesg *mesg)
{
	if(mesg -> statu == UNKNOW)
	{
		char *ret = "HTTP/1.1 404 NOT FOUND\r\nContent-Type: text/html\r\n\r\n <h1>NO THIS METHOD! </h1>"; 
		send(sd, ret, strlen(ret)*sizeof(char), 0);
		return -1;
	}

	const char *path = mesg -> path;
	if(deny_http) {
		char *ret = "HTTP/1.1 301 MOVED PERMANENTLY\r\nLocation: https://127.0.0.1"; 
		send(sd, ret, strlen(ret)*sizeof(char), 0);
		send(sd, mesg->url_path, strlen(mesg->url_path)*sizeof(char), 0);
		send(sd, "\r\n\r\n", 4*sizeof(char), 0);
		return 0;
	}

	int file = open(path, O_RDONLY);
	if(file < 0)
	{
		if(errno == ENOENT)
		{
			char *ret = "HTTP/1.1 404 NOT FOUND\r\nContent-Type: text/html\r\n\r\n <h1>404 NOT FOUND! </h1>"; 
			send(sd, ret, strlen(ret)*sizeof(char), 0);
			return -1;
		} else {
			perror("open()");
			return -1;
		}
	}

	struct stat file_stat;
	fstat(file, &file_stat);
	if(!S_ISREG(file_stat.st_mode))
	{
		char *ret = "HTTP/1.1 404 NOT FOUND\r\nContent-Type: text/html\r\n\r\n <h1>404 NOT FOUND! </h1>"; 
		send(sd, ret, strlen(ret)*sizeof(char), 0);
		close(file);
		return -1;
	}

	char* ret = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n";
	send(sd, ret, strlen(ret)*sizeof(char), 0);

	char buf[1024];
	while(1)
	{
		int nread;
		nread = read(file, buf, 1024);
		if(nread < 0)
		{
			perror("read()");
			close(file);
			break;
		}
		if(nread == 0)
		{
			close(file);
			break;
		}
		send(sd, buf, nread, 0);
	}
	
	return 0;
}

int setSocket(int *psd, int port)
{
	struct sockaddr_in laddr;
	int sd;

	sd = socket(AF_INET, SOCK_STREAM, 0);
	*psd = sd;
	if (sd < 0)
	{
		perror("socket()");
		return -1;
	}

	int val = 1;
	if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
	{
		perror("setsockopt()");
		return -1;
	}

	laddr.sin_family = AF_INET;
	laddr.sin_port = htons(port);
	inet_pton(AF_INET, "0.0.0.0", &laddr.sin_addr);

	if(bind(sd, (void *)&laddr, sizeof(laddr)) < 0)
	{
		perror("bind()");
		return -1;
	}

	if(listen(sd, 256) < 0)
	{
		perror("listen()");
		return -1;
	}

	return 0;
}

int isRoot()
{
	if (getuid() != 0)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

SSL_CTX* initServerCTX(void)
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;
	OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
	SSL_load_error_strings();   /* load all error messages */
	method = TLS_server_method();  /* create new server-method instance */
	ctx = SSL_CTX_new(method);   /* create new context from method */
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void loadCertificates(SSL_CTX* ctx, char* cert_file, char* key_file)
{
	/* set the local certificate from cert_file */
	if ( SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* set the private key from key_file (may be the same as cert_file) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	if ( !SSL_CTX_check_private_key(ctx) )
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}

void showCerts(SSL* ssl)
{
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
	if ( cert != NULL )
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}
	else
		printf("No certificates.\n");
}

void* httpServer(void *arg)
{
	int sd;
	if(setSocket(&sd, HTTP_PORT) < 0)
	{
		perror("setsocket()");
		pthread_exit(NULL);
	}

	struct sockaddr_in raddr;
	socklen_t raddr_len = sizeof(raddr);

	while(1)
	{
		int rvsd = accept(sd, (void *)&raddr, &raddr_len); 
		if(rvsd < 0)
		{
			perror("accept()");
			close(sd);
			pthread_exit(NULL);
		}

		char ipstr[IPSTRSIZE];
		inet_ntop(AF_INET, &raddr.sin_addr, ipstr, IPSTRSIZE);
		printf("Client:%s:%d\n", ipstr, ntohs(raddr.sin_port));

		http(rvsd);

		if(close(rvsd) < 0)
		{
			perror("close()");
			close(sd);
			pthread_exit(NULL);
		}
	}
	close(sd);
	pthread_exit(NULL);
}

void* httpsServer(void *arg)
{
	int sd;
	SSL_CTX *ctx;

	SSL_library_init();
	ctx = initServerCTX();
	loadCertificates(ctx, "mycert.pem", "mycert.pem");
	
	if(setSocket(&sd, HTTPS_PORT) < 0)
	{
		perror("setsocket()");
		pthread_exit(NULL);
	}

	struct sockaddr_in raddr;
	socklen_t raddr_len = sizeof(raddr);
	SSL *ssl;

	while(1)
	{
		int rvsd = accept(sd, (void *)&raddr, &raddr_len); 
		if(rvsd < 0)
		{
			perror("accept()");
			close(sd);
			pthread_exit(NULL);
		}

		char ipstr[IPSTRSIZE];
		inet_ntop(AF_INET, &raddr.sin_addr, ipstr, IPSTRSIZE);
		printf("Client:%s:%d\n", ipstr, ntohs(raddr.sin_port));

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, rvsd);

		//http(rvsd);
		https(ssl);

		SSL_free(ssl);
		if(close(rvsd) < 0)
		{
			perror("close()");
			close(sd);
			pthread_exit(NULL);
		}
	}
	close(sd);
	pthread_exit(NULL);
}

int readFirstLine(Mesg *mesg, char *line)
{
	int rightmethod = 0;
	for(int i = 0; ReqMethod[i] != NULL; i++)
	{
		//fputs(ReqMethod[i],stdout);
		if(strncmp(line, ReqMethod[i], strlen(ReqMethod[i])) == 0)
		{
			mesg -> statu = i;
			char* path_start = index(line, ' ')+1;
			char* path_end = rindex(line, ' ');
			strncat(mesg->path, path_start, path_end-path_start);
			strncpy(mesg->url_path, path_start, path_end-path_start);
			(mesg->url_path)[path_end-path_start] = '\0';
			rightmethod = 1;
			break;
		}
	}
	if(rightmethod == 0)
	{
		mesg -> statu = UNKNOW;
	}
	return 0;
}
