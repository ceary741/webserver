#ifndef _HTTPSERVER__H__
#define _HTTPSERVER__H__

#define ROOTPATH "/home/ceary/webserver/www"
#define SDWPATH "/sdw/"
#define PORT 443

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
	char *para[PARANUM];
	uint32_t ip;
	uint16_t port;
	int isSdw;
}Mesg;

int setsocket(int *sd);
void freemesg(Mesg *mesg);

int https(SSL *ssl);

int httpsread(SSL *ssl, Mesg *mesg);
int httpssend(SSL *ssl, const Mesg *mesg);

int OpenListener(int port);
int isRoot();
SSL_CTX* InitServerCTX(void);
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
void ShowCerts(SSL* ssl);
void Servlet(SSL* ssl); /* Serve the connection -- threadable */

#endif

