#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <strings.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
//#include "unp.h"
//#include "addrinfo.h"
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <pthread.h>
// no port number in raw socket

#define BUFSIZE 1500
#define NI_MAXHOST	1025
//#define SOCK_PATH "/Home/Downloads/echo_socket"

char recvbuf[BUFSIZE];
char sendbuf[BUFSIZE];
char* host;
int datalen;  //after ICMP header
u_short dport, sport;
int no_of_sent;
int no_of_probes,ttl, max_ttl, verbose;
int sendfd, recvfd; //send on UDP socket, recv on raw ICMP socket
pid_t pid;
int gotalarm;
int done=0,seq=0;

struct rec   //outgoing UDP data
{
	u_short rec_seq;
	u_short rec_ttl;
	struct timeval rec_tv;
};

void err_sys(const char* x) 
{ 
    perror(x); 
    exit(1); 
}

void sig_alrm(int signo)// for output or multithreading
{
	gotalarm = 1;//flag set after alarm occurred
	return;
}

char * icmpcode_v4(int code)
{
	switch (code) {
	case  0:	return("network unreachable");
	case  1:	return("host unreachable");
	case  2:	return("protocol unreachable");
	case  3:	return("port unreachable");
	case  4:	return("fragmentation required but DF bit set");
	case  5:	return("source route failed");
	case  6:	return("destination network unknown");
	case  7:	return("destination host unknown");
	case  8:	return("source host isolated (obsolete)");
	case  9:	return("destination network administratively prohibited");
	case 10:	return("destination host administratively prohibited");
	case 11:	return("network unreachable for TOS");
	case 12:	return("host unreachable for TOS");
	case 13:	return("communication administratively prohibited by filtering");
	case 14:	return("host recedence violation");
	case 15:	return("precedence cutoff in effect");
	default:	return("[unknown code]");
	}
}

int recv_v4(int, struct timeval*);
void sig_alrm(int);
void traceloop(void);
void tv_sub(struct timeval *out, struct timeval *in)
{
	if ( (out->tv_usec -= in->tv_usec) < 0) {	/* out -= in */
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}


struct proto
{
	const char *(*icmpcode)(int);
	int (*recv)(int, struct timeval *);  //sa is sock addr
	struct sockaddr *sasend;  // send fom getaddrinfo, dest addr
	struct sockaddr *sarecv;  
	struct sockaddr *salast;  //last for receiving
	struct sockaddr *sabind;  // for binding source port
	socklen_t salen;
	int icmpproto;  // IPPROTO_xxx value for icmp
	int ttllevel;  //level to set ttl
	int ttloptname;  //name to set ttl
}*pr;


struct proto proto_v4 = {icmpcode_v4, recv_v4, NULL,NULL,NULL,NULL,0,IPPROTO_ICMP, IPPROTO_IP, IP_TTL};//defaults
int datalen = sizeof(struct rec);
int max_ttl = 30;
int no_of_probes = 3;
u_short dport = 32768 + 666;

struct addrinfo * host_serv(const char *host, const char *serv, int family, int socktype)
{
	int	n;
	struct addrinfo	hints, *res;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;	/* always return canonical name */
	hints.ai_family = family;		/* AF_UNSPEC, AF_INET, AF_INET6, etc. */
	hints.ai_socktype = socktype;	/* 0, SOCK_STREAM, SOCK_DGRAM, etc. */

	if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0)
		return(NULL);

	return(res);	/* return pointer to first on linked list */
}

struct addrinfo * Host_serv(const char *host, const char *serv, int family, int socktype)
{
	int	n;
	struct addrinfo	hints, *res;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;	/* always return canonical name */
	hints.ai_family = family;		/* 0, AF_INET, AF_INET6, etc. */
	hints.ai_socktype = socktype;	/* 0, SOCK_STREAM, SOCK_DGRAM, etc. */

	if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0)
	{
		printf("host_serv error for %s, %s: %s\n",
				 (host == NULL) ? "(no hostname)" : host,
				 (serv == NULL) ? "(no service name)" : serv,
				 gai_strerror(n));
		exit(0);
	}

	return(res);	/* return pointer to first on linked list */
}

char * sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
    static char str[128];		/* Unix domain is largest */

	switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in	*sin = (struct sockaddr_in *) sa;

		if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
			return(NULL);
		return(str);
	}
	default:
		snprintf(str, sizeof(str), "sock_ntop_host: unknown AF_xxx: %d, len %d",
				 sa->sa_family, salen);
		return(str);
	}
    return (NULL);
}

char * Sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
	char *ptr;

	if ( (ptr = sock_ntop_host(sa, salen)) == NULL)
		err_sys("sock_ntop_host error");	/* inet_ntop() sets errno */
	return(ptr);
}

void sock_set_port(struct sockaddr *sa, socklen_t salen, int port)
{
	switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in	*sin = (struct sockaddr_in *) sa;

		sin->sin_port = port;
		return;
	}
	}
    return;
}

int sock_cmp_addr(const struct sockaddr *sa1, const struct sockaddr *sa2, socklen_t salen)
{
	if (sa1->sa_family != sa2->sa_family)
		return(-1);

	switch (sa1->sa_family) {
	case AF_INET: {
		return(memcmp( &((struct sockaddr_in *) sa1)->sin_addr,
					   &((struct sockaddr_in *) sa2)->sin_addr,
					   sizeof(struct in_addr)));
	}
	}
    return (-1);
}

int main(int argc, char ** argv)
{
	struct addrinfo *ai;
	char *h;
	int c;
	opterr = 0;

	while((c=getopt(argc, argv, "m:v"))!=-1)
	{
		switch (c)
		{
			case 'm':
				if((max_ttl=atoi(optarg))<=1)
				{
					printf("invalid -m value\n");
					exit(0);
				}
				break;
			case 'v':
				verbose++;
				break;
			case '?':
				printf("unrecognized %c\n", c);
				exit(0);
				break;
		}
	}
	if(optind!=argc-1)
	{
		printf("usage: traceroute [-m <maxttl> -v] <hostname>\n");
		exit(0);
	}
	host = argv[optind];

	pid = getpid();
	signal(SIGALRM, sig_alrm);
	ai = Host_serv(host,NULL,0,0);
	h = Sock_ntop_host(ai->ai_addr, ai->ai_addrlen);
	printf("Traceroute to %s (%s) : %d hops max, %d data bytes\n", ai->ai_canonname? ai->ai_canonname :h, h, max_ttl, datalen);
	if(ai->ai_family == AF_INET)
		pr = &proto_v4;
	else
	{
		printf("unknown address family %d\n",ai->ai_family);
		exit(0);
	}
	pr->sasend = ai->ai_addr;
	pr->sarecv = calloc(1,ai->ai_addrlen);
	pr->salast = calloc(1,ai->ai_addrlen);
	pr->sabind = calloc(1,ai->ai_addrlen);
	pr->salen = ai->ai_addrlen;

	traceloop();
	exit(0);
}


static void *doit(void *arg){

	struct timeval tvrecv;
	pthread_detach(pthread_self());
	struct rec *rec;
	int seq = (int) arg;
	//printf("new thread seq:%d",seq);
	int code;
    double rtt;
    int probe;
	for(probe = 0; probe< no_of_probes; probe++)
		{
			rec = (struct rec *) sendbuf;
			rec->rec_seq = ++seq;
			rec->rec_ttl = ttl;
			gettimeofday(&rec->rec_tv, NULL);
			sock_set_port(pr->sasend, pr->salen, htons(dport + seq));
			sendto(sendfd, sendbuf, datalen, 0 , pr->sasend, pr->salen);
			if((code = (*pr->recv)(seq, &tvrecv)) == -3)
				printf(" *\n"); //timeout, no reply
			else
			{
				char str[NI_MAXHOST];
				if(sock_cmp_addr(pr->sarecv, pr->salast, pr->salen)!=0)
				{
					if(getnameinfo(pr->sarecv, pr->salen, str, sizeof(str),NULL,0,0)==0)
						printf("%s (%s)\n", str, Sock_ntop_host(pr->sarecv, pr->salen));
					else
						printf("%s\n", Sock_ntop_host(pr->sarecv, pr->salen));
					memcpy(pr->salast, pr->sarecv, pr->salen);
				}
				tv_sub(&tvrecv, &rec->rec_tv);
				rtt = tvrecv.tv_sec * 1000.0 + tvrecv.tv_usec / 1000.0;
				printf("rtt = %f ms\n",rtt );
				if(code == -1) //unreachable at dest,////////work done
					done++;
				else if(code>=0)
					printf("ICMP %s\n", (*pr->icmpcode)(code));
			}
			fflush(stdout);
		}
}


void traceloop(void)
{
	
	pthread_t tid[31];

	if((recvfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto))<0)
		err_sys("socket error");//recvfd
	setuid(getuid());
	sendfd = socket(pr->sasend->sa_family, SOCK_DGRAM, 0);//sendfd
	pr->sabind->sa_family = pr->sasend->sa_family;
	sport = (getpid()& 0xffff)| 0x8000;
	sock_set_port(pr->sabind, pr->salen, htons(sport));
	bind(sendfd,pr->sabind, pr->salen);
	sig_alrm(SIGALRM);

	/*for(ttl=1;ttl<max_ttl && done == 0;ttl++){
		pthread_create(&tid[ttl],NULL,&doit,NULL);
		//pthread_detach(tid);
		printf("New thread Creation %d\n\n\n\n",tid[ttl]);
	}
	for(int i=1;i<max_ttl;i++){
		pthread_join(&tid[i],NULL);
		//pthread_detach(tid);
		printf("thread joined %d,%d\n\n\n\n",tid[i],i);
	}*/

	for(ttl = 1; ttl<=max_ttl && done == 0; ttl++)
	{
		
		setsockopt(sendfd, pr->ttllevel, pr->ttloptname, &ttl,sizeof(int));
		bzero(pr->salast, pr->salen);
		//printf("ttl value = %d\n", ttl);
		fflush(stdout);
		pthread_create(&tid[ttl],NULL,&doit,(void *) seq);
		seq = seq+3;
	}

	while(done==0){};
	/*for(int i=1;i<=max_ttl;i++){
		pthread_join(&tid[i],NULL);
		//pthread_detach(tid);
		printf("thread joined %d,%d\n\n\n\n",tid[i],i);
	}*/
}

int recv_v4(int seq, struct timeval* tv)
{
	//printf("seq:%d\n",seq);
	int hlen1, hlen2, icmplen, ret;
	socklen_t len;
	ssize_t n;
	struct ip * ip, *hip;
	struct icmp * icmp;
	struct udphdr *udp;
	gotalarm = 0;
	alarm(3);
	for(;;)
	{
			if(gotalarm)// wait type kuch
				return (-3); ///alarm expired timeout
			len = pr->salen;
			
			//printf("%s\n", recvbuf );
			n = recvfrom(recvfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);
			//printf("%d\n",  GetLastError());
			if(n<0)
			{
			if(errno == EINTR)
				continue;
			else
				err_sys("recvfrom error");
			}
			ip = (struct ip*) recvbuf;//start of ip header
			hlen1 = ip->ip_hl <<2;/// length of ip header
			icmp = (struct icmp*)(recvbuf + hlen1);///start of icmp header
			if((icmplen = n-hlen1)<8)
				continue;//not enough
			if(icmp->icmp_type == ICMP_TIMXCEED && icmp->icmp_code == ICMP_TIMXCEED_INTRANS)
			{
				if(icmplen<(8+ sizeof(struct ip)))
					continue;
				hip =  (struct ip*)(recvbuf + hlen1 + 8);
				hlen2 = hip->ip_hl <<2;
				if(icmplen<(8+ hlen2 + 4))
					continue;
				udp = (struct udphdr*)(recvbuf + hlen1 + 8 + hlen2);
				if(hip->ip_p == IPPROTO_UDP && udp->source == htons(sport) && udp->dest == htons(dport + seq))
				{
					ret = -2;//intermediate router
					break;
				}
			}

			else if(icmp->icmp_type == ICMP_UNREACH)
			{
				if(icmplen<(8+ sizeof(struct ip)))
					continue;
				hip =  (struct ip*)(recvbuf + hlen1 + 8);
				hlen2 = hip->ip_hl <<2;
				if(icmplen<(8+ hlen2 + 4))
					continue;
				udp = (struct udphdr*)(recvbuf + hlen1 + 8 + hlen2);
				if(hip->ip_p == IPPROTO_UDP && udp->source == htons(sport) && udp->dest == htons(dport + seq))
				{
					if(icmp->icmp_code == ICMP_UNREACH_PORT)
						ret = -1;//destination
					else
						ret = icmp->icmp_code;
					break;
				}
			}
			if (verbose)
			{
				printf(" from %s : type = %d, code = %d\n", Sock_ntop_host(pr->sarecv,pr->salen),icmp->icmp_type, icmp->icmp_code);
			}
		
	} 
	alarm(0);
	gettimeofday(tv,NULL);
	return (ret);
}
