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

int main(void)
{
	int sd;
	SSL_CTX *ctx;

	SSL_library_init();
	ctx = InitServerCTX();
	LoadCertificates(ctx, "mycert.pem", "mycert.pem");
	
	if(setsocket(&sd) < 0)
	{
		perror("setsocket()");
		exit(1);
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
			exit(1);
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
			exit(1);
		}
	}
	close(sd);
	exit(0);
}

int https(SSL *ssl)
{
	Mesg *mesg = malloc(sizeof(Mesg));
	mesg->para[0] = NULL;

	if(httpsread(ssl, mesg) < 0)
	{
		fprintf(stderr, "There is a error request\n");
		freemesg(mesg);
		return -1;
	}

	if(httpssend(ssl, mesg) < 0)
	{
		fprintf(stderr, "There is an error when send\n");
		freemesg(mesg);
		return -1;
	}
	freemesg(mesg);
	return 0;
}

void freemesg(Mesg *mesg)
{
	int i;
	for(i = 1; i < PARANUM; i++)
	{
		if(mesg->para[i] == NULL)
			break;
		free(mesg->para[i]);
	}
	free(mesg);

	return;
}

int httpsread(SSL *ssl, Mesg *mesg)
{
	char buf[BUFSIZE];
	int bytes;

	if(SSL_accept(ssl) < 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	ShowCerts(ssl);
	bytes = SSL_read(ssl, buf, sizeof(buf));
	if(bytes == BUFSIZE) {
		fprintf(stderr, "GET is too long!\n");
		return -1;
	}
	buf[bytes] = '\0';
	char *path = mesg -> path;
	strcpy(path, ROOTPATH);

	char *line = malloc(BUFSIZE);
	char *line_start = buf;
	char *line_end = buf;
	int cnt = 0;
	while(1)
	{
		/*todo
		  copy each line to line
		  */
		line_end = index(line_start, '\n');
		strncpy(line, line_start, line_end-line_start+1);
		line[line_end-line_start+1] = '\0';
		fputs(line, stdout);
		if(strcmp(line, "\r\n") == 0)
			break;

		if(cnt == 0)
		{
			int rightmethod = 0;
			for(int i = 0; ReqMethod[i] != NULL; i++)
			{
				fputs(ReqMethod[i],stdout);
				if(strncmp(line, ReqMethod[i], strlen(ReqMethod[i])) == 0)
				{
					mesg -> statu = i;
					char* path_start = index(line, ' ')+1;
					char* path_end = rindex(line, ' ');
					strncat(path, path_start, path_end-path_start);
					//if(strncmp(start, SDWPATH, 5) == 0)
					//	mesg -> isSdw = 1;
					rightmethod = 1;
					break;
				}
			}
			if(rightmethod == 0)
			{
				mesg -> statu = UNKNOW;
			}
		}

		line_start = line_end + 1;
		cnt++;
	}

	free(line);

	//mesg->para[0] = "sdw";
	if(mesg -> statu != GET)  //only support get method
	{
		mesg -> statu = UNKNOW;
	}
	//else {
	//	char* para_pos = index(mesg->path, '?');
	//	if(para_pos != NULL)
	//		*para_pos = '\0';
	//	char  **ptolast = mesg -> para;
	//	int cnt = 0;
	//	ptolast++;
	//	while(para_pos != NULL)
	//	{
	//		char *start = para_pos + 1;
	//		para_pos = index(start, '&');
	//		if(para_pos != NULL)
	//			*para_pos = '\0';
	//		int len = strlen(start) + 1;
	//		if(len > PARASIZE)
	//		{
	//			fprintf(stderr, "para is too long\n");
	//			len = PARASIZE;
	//		}
	//		
	//		*ptolast = malloc(sizeof(char)*len);
	//		strncpy(*ptolast, start, len);
	//		//printf("para: %s len: %d\n", start, len);
	//		(*ptolast)[len-1] = '\0';

	//		ptolast++;
	//		cnt++;
	//		if(cnt == PARANUM-1)
	//		{
	//			break;
	//		}
	//		//printf("%s %s \n", (mesg->para)[1], (mesg->para)[2]);
	//	}
	//	*ptolast = NULL;
	//}
	return 0;
}

int httpssend(SSL *ssl, const Mesg *mesg)
{
	if(mesg -> statu == UNKNOW)
	{
		char *ret = "HTTP/1.1 404 NOT FOUND\r\nContent-Type: text/html\r\n\r\n <h1>NO THIS METHOD! </h1>"; 
		SSL_write(ssl, ret, strlen(ret)/sizeof(char));
		return -1;
	}
	const char *path = mesg -> path;
	int file = open(path, O_RDONLY);
	if(file < 0)
	{
		if(errno == ENOENT)
		{
			char *ret = "HTTP/1.1 404 NOT FOUND\r\nContent-Type: text/html\r\n\r\n <h1>404 NOT FOUND! </h1>"; 
			SSL_write(ssl, ret, strlen(ret)/sizeof(char));
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
		SSL_write(ssl, ret, strlen(ret)/sizeof(char));
		close(file);
		return -1;
	}

	char* ret = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n";
	SSL_write(ssl, ret, strlen(ret)/sizeof(char));

	//if(mesg -> isSdw)
	//{
	//	pid_t pid = fork();
	//	if(pid < 0)
	//	{
	//		perror("fork()");
	//		close(file);
	//		return -1;
	//	}
	//	else if(pid > 0)
	//	{
	//		wait(NULL);
	//	}
	//	else
	//	{
	//		dup2(sd, 1);
	//		fexecve(file, mesg -> para, environ); 
	//	}


	//} else 
	{
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
	}

	//printf("sended!!!\n");
	
	return 0;
}

int setsocket(int *psd)
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
	laddr.sin_port = htons(PORT);
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

SSL_CTX* InitServerCTX(void)
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

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	/* set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
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

void ShowCerts(SSL* ssl)
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

void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
	char buf[1024] = {0};
	int sd, bytes;
	const char* ServerResponse="<\\Body>\
								<Name>aticleworld.com</Name>\
								<year>1.5</year>\
								<BlogType>Embedede and c\\c++<\\BlogType>\
								<Author>amlendra<Author>\
								<\\Body>";
	const char *cpValidMessage = "<Body>\
								  <UserName>aticle<UserName>\
								  <Password>123<Password>\
								  <\\Body>";
	if ( SSL_accept(ssl) == -1 )     /* do SSL-protocol accept */
		ERR_print_errors_fp(stderr);
	else
	{
		ShowCerts(ssl);        /* get any certificates */
		bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
		buf[bytes] = '\0';
		printf("Client msg: \"%s\"\n", buf);
		if ( bytes > 0 )
		{
			if(strcmp(cpValidMessage,buf) == 0)
			{
				SSL_write(ssl, ServerResponse, strlen(ServerResponse)); /* send reply */
			}
			else
			{
				SSL_write(ssl, "Invalid Message", strlen("Invalid Message")); /* send reply */
			}
		}
		else
		{
			ERR_print_errors_fp(stderr);
		}
	}
	sd = SSL_get_fd(ssl);       /* get socket connection */
	SSL_free(ssl);         /* release SSL state */
	close(sd);          /* close connection */
}
