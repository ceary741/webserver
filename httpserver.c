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
	if(setsocket(&sd) < 0)
	{
		perror("setsocket()");
		exit(1);
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
			exit(1);
		}

		char ipstr[IPSTRSIZE];
		inet_ntop(AF_INET, &raddr.sin_addr, ipstr, IPSTRSIZE);
		printf("Client:%s:%d\n", ipstr, ntohs(raddr.sin_port));

		http(rvsd);
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

int http(int sd)
{
	Mesg *mesg = malloc(sizeof(Mesg));
	mesg->para[0] = NULL;

	if(httpread(sd, mesg) < 0)
	{
		fprintf(stderr, "There is a error request\n");
		freemesg(mesg);
		return -1;
	}

	if(httpsend(sd, mesg) < 0)
	{
		fprintf(stderr, "There is an error when send\n");
		freemesg(mesg);
		return -1;
	}
	freemesg(mesg);
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

int httpread(int sd, Mesg *mesg)
{
	FILE *recv;
	int recvfd = dup(sd);
	recv = fdopen(recvfd, "r");
	
	char *line;
	size_t len = 0;
	ssize_t nread;
	char *path = mesg -> path;
	strcpy(path, ROOTPATH);

	mesg -> isSdw = 0;

	int cnt = 0;
	while(1)
	{
		nread = getline(&line, &len, recv);
		if(nread < 0)
		{
			fclose(recv);
			free(line);
			return -1;
		}
		fputs(line, stdout);
		if(strcmp(line, "\r\n") == 0)
			break;

		if(cnt == 0)
		{
			int rightmethod = 0;
			for(int i = 0; ReqMethod[i] != NULL; i++)
			{
				if(strncmp(line, ReqMethod[i], strlen(ReqMethod[i])) == 0)
				{
					mesg -> statu = i;
					char* start = index(line, ' ')+1;
					char* end = rindex(line, ' ');
					strncat(path, start, end-start);
					if(strncmp(start, SDWPATH, 5) == 0)
						mesg -> isSdw = 1;
					rightmethod = 1;
					break;
				}
			}
			if(rightmethod == 0)
			{
				mesg -> statu = UNKNOW;
			}
		}
		cnt++;
	}
	fclose(recv);
	free(line);

	mesg->para[0] = "sdw";
	if(mesg -> statu != GET)  //only support get method
	{
		mesg -> statu = UNKNOW;
	} else {
		char* para_pos = index(mesg->path, '?');
		if(para_pos != NULL)
			*para_pos = '\0';
		char  **ptolast = mesg -> para;
		int cnt = 0;
		ptolast++;
		while(para_pos != NULL)
		{
			char *start = para_pos + 1;
			para_pos = index(start, '&');
			if(para_pos != NULL)
				*para_pos = '\0';
			int len = strlen(start) + 1;
			if(len > PARASIZE)
			{
				fprintf(stderr, "para is too long\n");
				len = PARASIZE;
			}
			
			*ptolast = malloc(sizeof(char)*len);
			strncpy(*ptolast, start, len);
			//printf("para: %s len: %d\n", start, len);
			(*ptolast)[len-1] = '\0';

			ptolast++;
			cnt++;
			if(cnt == PARANUM-1)
			{
				break;
			}
			//printf("%s %s \n", (mesg->para)[1], (mesg->para)[2]);
		}
		*ptolast = NULL;
	}
	return 0;
}

int httpsend(int sd, const Mesg *mesg)
{
	if(mesg -> statu == UNKNOW)
	{
		char *ret = "HTTP/1.1 404 NOT FOUND\r\nContent-Type: text/html\r\n\r\n <h1>NO THIS METHOD! </h1>"; 
		send(sd, ret, strlen(ret)/sizeof(char), 0);
		return -1;
	}
	const char *path = mesg -> path;
	int file = open(path, O_RDONLY);
	if(file < 0)
	{
		if(errno == ENOENT)
		{
			char *ret = "HTTP/1.1 404 NOT FOUND\r\nContent-Type: text/html\r\n\r\n <h1>404 NOT FOUND! </h1>"; 
			send(sd, ret, strlen(ret)/sizeof(char), 0);
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
		send(sd, ret, strlen(ret)/sizeof(char), 0);
		close(file);
		return -1;
	}

	char* ret = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n";
	send(sd, ret, strlen(ret)/sizeof(char), 0);

	if(mesg -> isSdw)
	{
		pid_t pid = fork();
		if(pid < 0)
		{
			perror("fork()");
			close(file);
			return -1;
		}
		else if(pid > 0)
		{
			wait(NULL);
		}
		else
		{
			dup2(sd, 1);
			fexecve(file, mesg -> para, environ); 
		}


	} else {
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
