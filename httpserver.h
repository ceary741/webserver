#ifndef _HTTPSERVER__H__
#define _HTTPSERVER__H__

#define ROOTPATH "/Users/ceary/webserver/webserver/www"
#define SDWPATH "/sdw/"
#define HTTP_PORT 80
#define HTTPS_PORT 443

#define IPSTRSIZE 64
#define PARASIZE 64
#define PATHSIZE 256
#define PARANUM 16
#define BUFSIZE 1024

extern char **environ;

typedef
enum Status{
	GET,
	POST,
	HEAD,
	UNKNOW,
} Status;

typedef
struct Mesg{
	Status statu;
	char path[PATHSIZE];
	char url_path[PATHSIZE];
	char *para[PARANUM];
	uint32_t ip;
	uint16_t port;
}Mesg;

int setSocket(int *sd, int port);
void freeMesg(Mesg *mesg);
int readFirstLine(Mesg *mesg, char *line);

int https(SSL *ssl);
int httpsRead(SSL *ssl, Mesg *mesg);
int httpsSend(SSL *ssl, const Mesg *mesg);

int http(int sd);
int httpRead(int sd, Mesg *mesg);
int httpSend(int sd, const Mesg *mesg);

int openListener(int port);
int isRoot();
SSL_CTX* initServerCTX(void);
void loadCertificates(SSL_CTX* ctx, char* cert_file, char* key_file);
void showCerts(SSL* ssl);

void* httpServer(void* arg);
void* httpsServer(void* arg);

#endif

