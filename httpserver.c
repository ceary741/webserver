#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
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

const char *type_mp4 = "video/mp4";
const char *type_html = "text/html";

char const *ReqMethod[] = 
{
	[GET]	"GET",
	[POST]	"POST",
	[HEAD]	"HEAD",
	NULL
};

char const *HeaderPara[] = 
{
	"Range:",
	"Sec-Fetch-Dest:",
	NULL
};

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
	{
		struct timespec ts;
		int s;
		if(clock_gettime(CLOCK_REALTIME, &ts) == -1) {
			perror("clock_gettime()");
			exit(-1);
		}
		ts.tv_sec += 5;
		s = pthread_timedjoin_np(pid_http, NULL, &ts);
		if (s == 0) {
			if(pthread_create(&pid_http, NULL, httpServer, NULL) != 0) {
				perror("pthread_create()");
				exit(-1);
			}
		}

		if(clock_gettime(CLOCK_REALTIME, &ts) == -1) {
			perror("clock_gettime()");
			exit(-1);
		}
		ts.tv_sec += 5;
		s = pthread_timedjoin_np(pid_https, NULL, &ts);
		if (s == 0) {
			if(pthread_create(&pid_https, NULL, httpsServer, NULL) != 0) {
				perror("pthread_create()");
				exit(-1);
			}
		}
	}
	return 0;
}

int https(SSL *ssl)
{
	Mesg *mesg = malloc(sizeof(Mesg));
	mesg->range_start = 0;
	mesg->range_end = 0;
	mesg->ret_data = 1;
	mesg->ret_length = 0;

	if(httpsRead(ssl, mesg) < 0)
	{
		fprintf(stderr, "There is an error when read\n");
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
		if(strcmp(line, "\r\n") == 0)
			break;

		if(cnt == 0)
		{
			readFirstLine(mesg, line);
		}
		else
		{
			//printf(line);
			if(readHeaders(mesg, line) != 0)
			{
				free(line);
				return -1;
			}
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

int httpsSend(SSL *ssl, Mesg *mesg)
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
			fprintf(stderr, "There is no file %s\n", mesg -> path);
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
		fprintf(stderr, "This file %s is diretory\n", mesg -> path);
		close(file);
		return -1;
	}

	const char *content_type = type_html;
	char *dot_pos = rindex(mesg->path, '.');
	if(strncmp("mp4", dot_pos+1, strlen("mp4")) == 0)
	{
		content_type = type_mp4;
		if(mesg->ret_document)
		{
			mesg->ret_data = 0;
		}
	}

	uint64_t range_start = mesg->range_start;
	uint64_t range_end = mesg->range_end;
	off_t len = lseek(file, 0, SEEK_END);
	if(range_end == 0)
	{
		range_end = len-1;
	}
	if(len <= range_end || range_start > range_end)
	{
		fprintf(stderr, "range in header is invalid!\n");
		return -1;
	}
	if(range_end - range_start > 1024*1024 && range_end == 0) {
		range_end = range_start + 1024*1024;
		mesg -> range_end = range_end;
	}

	lseek(file, range_start, SEEK_SET);

	if(mesg->range_start == 0 && mesg->range_end == 0)
	{
		char *ret = malloc(BUFSIZE);
		sprintf(ret, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nConnection: close\r\n", content_type);
		SSL_write(ssl, ret, strlen(ret)*sizeof(char));
		free(ret);
	} else 
	{
		char *ret = malloc(BUFSIZE);
		sprintf(ret, "HTTP/1.1 206 Partial Content\r\nContent-Type: %s\r\nConnection: close\r\n", content_type);
		SSL_write(ssl, ret, strlen(ret)*sizeof(char));
		sprintf(ret, "Content-Range: bytes %ld-%ld/%ld\r\n", range_start, range_end, len);
		printf(ret);
		SSL_write(ssl, ret, strlen(ret)*sizeof(char));
		sprintf(ret, "Length: %ld\r\n", range_end - range_start + 1);
		SSL_write(ssl, ret, strlen(ret)*sizeof(char));
		free(ret);
	}

	if(mesg->ret_length)
	{
		char *ret = malloc(BUFSIZE);
		sprintf(ret, "Length: %ld\r\n", len);
		SSL_write(ssl, ret, strlen(ret)*sizeof(char));
		free(ret);
	}

	SSL_write(ssl, "\r\n", 2);

	if(mesg->ret_data == 0)
		return 0;
	char buf[1024*128];
	while(1)
	{
		int nread;
		int nread_w = range_end+1 - lseek(file, 0, SEEK_CUR);
		if(nread_w > 1024*32)
			nread_w = 1024*32;
		if(nread_w == 0)
		{
			close(file);
			break;
		}
		nread = read(file, buf, nread_w);
		if(nread < 0)
		{
			perror("read()");
			close(file);
			break;
		}
		int ret = SSL_write(ssl, buf, nread);
		printf("=");
		fflush(stdout);
		if(ret <= 0) {
			printf("ssl have closed\n");
			return -1;
		}
	}
	printf("\n");
	
	return 0;
}

int http(int sd)
{
	Mesg *mesg = malloc(sizeof(Mesg));
	mesg->range_start = 0;
	mesg->range_end = 0;
	mesg->ret_data = 1;
	mesg->ret_length = 0;

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
		//fputs(line, stdout);
		if(strcmp(line, "\r\n") == 0)
			break;

		if(cnt == 0)
		{
			readFirstLine(mesg, line);
		}
		else
		{
			readHeaders(mesg, line);
		}
		cnt++;
	}
	fclose(recv);
	free(line);

	if(mesg -> statu != GET)  //only support get method
		mesg -> statu = UNKNOW;
	return 0;
}

int httpSend(int sd, Mesg *mesg)
{
	if(mesg -> statu == UNKNOW)
	{
		char *ret = "HTTP/1.1 404 NOT FOUND\r\nContent-Type: text/html\r\n\r\n <h1>NO THIS METHOD! </h1>"; 
		send(sd, ret, strlen(ret)*sizeof(char), 0);
		return -1;
	}

	char *ret = "HTTP/1.1 301 MOVED PERMANENTLY\r\nLocation: https://10.0.0.1"; 
	send(sd, ret, strlen(ret)*sizeof(char), 0);
	send(sd, mesg->url_path, strlen(mesg->url_path)*sizeof(char), 0);
	send(sd, "\r\n\r\n", 4*sizeof(char), 0);
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
	if ( SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
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
	{
		//printf("No certificates.\n");
	}
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
	loadCertificates(ctx, "keys/cnlab.cert", "keys/cnlab.prikey");
	
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

		struct timeval tv;
		tv.tv_sec  = 1;
		tv.tv_usec = 0;
		setsockopt(rvsd, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(struct timeval));

		char ipstr[IPSTRSIZE];
		inet_ntop(AF_INET, &raddr.sin_addr, ipstr, IPSTRSIZE);
		printf("Client:%s:%d\n", ipstr, ntohs(raddr.sin_port));

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, rvsd);

		//SSL_set_connect_state(ssl);

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
	fputs(line, stdout);
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

int readHeaders(Mesg *mesg, char *line)
{
	for(int i = 0; HeaderPara[i] != NULL; i++)
	{
		//fputs(ReqMethod[i],stdout);
		if(strncmp(line, HeaderPara[i], strlen(HeaderPara[i])) == 0)
		{
			fputs(line, stdout);
			if(i == HEADER_RANGE){
				char *start_pos = index(line, '=')+1;
				char *end_pos = index(line, '-')+1;
				mesg->range_start = atoi(start_pos);
				if(mesg->range_start < 0)
					mesg->range_start = 0;
				mesg->range_end = atoi(end_pos);
				if(mesg->range_end != 0 && mesg->range_end <= mesg->range_start)
				{
					fprintf(stderr, "range in header is invalid!\n");
					return -1;
				}
			}
			else if(i == HEADER_SEC_FETCH_DEST) {
				char buf[BUFSIZE];
				char *start_pos = index(line, ':')+1;
				strncpy(buf, start_pos, BUFSIZE);
				char *trim_buf = trim(buf);
				if(strncmp(trim_buf, "document", strlen(trim_buf)) == 0) {
					mesg->ret_length = 1;
					mesg->ret_document = 1;
				}
			}
		} 
	}
	return 0;
}

char* trim(char *str) {
    char *end;
    while(isspace((unsigned char)*str)) str++;

    if(*str == 0)
        return NULL;

    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;

    *(end + 1) = '\0';
	return str;
}
