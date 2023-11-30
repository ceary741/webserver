#ifndef _HTTPSERVER__H__
#define _HTTPSERVER__H__

#define ROOTPATH "/home/ceary/webserver/www"
#define SDWPATH "/sdw/"
#define PORT 80

#define IPSTRSIZE 64
#define PARASIZE 64
#define PATHSIZE 256
#define PARANUM 16

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

int http(int sd);

int httpread(int sd, Mesg *mesg);
int httpsend(int sd, const Mesg *mesg);


#endif

