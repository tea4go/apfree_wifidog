/* vim: set et sw=4 sts=4 ts=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
 \********************************************************************/

/**
  @file util.c
  @brief Misc utility functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2006 Benoit Grégoire <bock@step.polymtl.ca>
  @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <net/if.h>

#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>

#include <string.h>
#include <netdb.h>
#include <ctype.h>

#include "util.h"
#include "debug.h"
#include "common.h"


/** @brief FD for icmp raw socket */
static int icmp_fd;

static unsigned short rand16(void);


/** Initialize the ICMP socket
 * @return A boolean of the success
 */
int
init_icmp_socket(void)
{
    int flags, oneopt = 1, zeroopt = 0;

    debug(LOG_DEBUG, "Creating ICMP socket");
    if ((icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1 ||
        (flags = fcntl(icmp_fd, F_GETFL, 0)) == -1 ||
        fcntl(icmp_fd, F_SETFL, flags | O_NONBLOCK) == -1 ||
        setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &oneopt, sizeof(oneopt)) ||
        setsockopt(icmp_fd, SOL_SOCKET, SO_DONTROUTE, &zeroopt, sizeof(zeroopt)) == -1) {
        debug(LOG_ERR, "Cannot create ICMP raw socket.");
        return 0;
    }
    return 1;
}

/** Close the ICMP socket. */
void
close_icmp_socket(void)
{
    debug(LOG_DEBUG, "Closing ICMP socket");
    close(icmp_fd);
}

/**
 * Ping an IP.
 * @param IP/host as string, will be sent to gethostbyname
 */
void
icmp_ping(const char *host)
{
    struct sockaddr_in saddr;
    struct {
        struct ip ip;
        struct icmp icmp;
    } packet;
    unsigned int i, j;
    int opt = 2000;
    unsigned short id = rand16();

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    inet_aton(host, &saddr.sin_addr);
#if defined(HAVE_SOCKADDR_SA_LEN)
    saddr.sin_len = sizeof(struct sockaddr_in);
#endif

    memset(&packet.icmp, 0, sizeof(packet.icmp));
    packet.icmp.icmp_type = ICMP_ECHO;
    packet.icmp.icmp_id = id;

    for (j = 0, i = 0; i < sizeof(struct icmp) / 2; i++)
        j += ((unsigned short *)&packet.icmp)[i];

    while (j >> 16)
        j = (j & 0xffff) + (j >> 16);

    packet.icmp.icmp_cksum = (j == 0xffff) ? j : ~j;

    if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
        debug(LOG_ERR, "icmp_ping() : setsockopt(): %s", strerror(errno));

    if (sendto(icmp_fd, (char *)&packet.icmp, sizeof(struct icmp), 0,
               (const struct sockaddr *)&saddr, sizeof(saddr)) == -1)
        debug(LOG_ERR, "icmp_ping() : sendto(): %s", strerror(errno));

    opt = 1;
    if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
        debug(LOG_ERR, "icmp_ping() : setsockopt(): %s", strerror(errno));

    return;
}

/** Get a 16-bit unsigned random number.
 * @return unsigned short a random number
 * 获取16位无符号随机数。
 */
static unsigned short
rand16(void)
{
    static int been_seeded = 0;

    if (!been_seeded) {
        unsigned int seed = 0;
        struct timeval now;

        /* not a very good seed but what the heck, it needs to be quickly acquired */
        gettimeofday(&now, NULL);
        seed = now.tv_sec ^ now.tv_usec ^ (getpid() << 16);

        srand(seed);
        been_seeded = 1;
    }

    /* Some rand() implementations have less randomness in low bits
     * than in high bits, so we only pay attention to the high ones.
     * But most implementations don't touch the high bit, so we
     * ignore that one. */
    return ((unsigned short)(rand() >> 15));
}

/*
 * Save pid of this wifidog in pid file
 * @param 'pf' as string, it is the pid file absolutely path
 */
void
save_pid_file(const char *pf)
{
    if (pf) {
        FILE *f = fopen(pf, "w");
        if (f) {
            fprintf(f, "%d\n", getpid());

            int ret = fclose(f);
            if (ret == EOF) /* check the return value of fclose */
                debug(LOG_ERR, "fclose() on file %s was failed (%s)", pf, strerror(errno));
        } else /* fopen return NULL, open file failed */
            debug(LOG_ERR, "fopen() on flie %s was failed (%s)", pf, strerror(errno));
    }

    return;
}


// liudf added 20160412
int
is_valid_ip(const char *ip)
{
	struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    return result != 0;
}

int 
is_valid_mac(const char *mac)
{
	int i = 0;
	int s = 0;

	while (*mac) {
		if (isxdigit(*mac)) {
			i++;
		} else if (*mac == ':' || *mac == '-') {
			if (i == 0 || i / 2 - 1 != s)
				break;
			++s;
		} else {
			s = -1;
		}
		++mac;
	}

	return (i == 12 && (s == 5 || s == 0));
}

/*
 * 0, FALSE; 1, TRUE
 */
int is_socket_valid(int sockfd)
{
	int err = 0;
	int errlen = sizeof(err);

    //SO_ERROR    int     获取错误状态并清除。
	//当函数成功时返回0。当发生错误时会返回-1，而错误原因会存放在外部变量errno中。
	if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
		debug(LOG_INFO, "is_socket_valid() : 网络连接有错误。错误码：%d，原因：%s", errno,strerror(errno));
		return 0;
	}

	if (err) {
		debug(LOG_INFO, "is_socket_valid() : 网络连接有错误。错误码：%d，原因：%s", errno,strerror(errno));
		return 0;
	}

	return 1;
}

// when sockfd is block, set timeout for connect
int 
wd_connect(int sockfd, const struct sockaddr *their_addr, socklen_t addrlen, int timeout)
{
	// Set non-blocking 
	long arg = fcntl(sockfd, F_GETFL, NULL); 
	arg |= O_NONBLOCK; 
	fcntl(sockfd, F_SETFL, arg); 
       	
	int res = connect(sockfd, their_addr, addrlen); 
	if ((res == -1) && (errno != EINPROGRESS)) {
		goto error;
	} else if (res == 0) {
		goto success;
	} else {
		fd_set fdset; 
		struct timeval tv; 
		int so_error = 0;
		int len = sizeof(so_error);

		tv.tv_sec = timeout; 
		tv.tv_usec = 0; 
		FD_ZERO(&fdset); 
		FD_SET(sockfd, &fdset);

		res = select(sockfd+1, NULL, &fdset, NULL, &tv);
		switch(res) {
		case 1: // data to read				
			getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
			if (so_error == 0) {
				goto success;
			}
			break;
		default: 
			break;
		}
	} 

error:
	return -1;
success:	
	// Set to blocking mode again... 
	arg = fcntl(sockfd, F_GETFL, NULL); 
	arg &= (~O_NONBLOCK); 
	fcntl(sockfd, F_SETFL, arg); 
	return 0;
}

#define	BUF_MAX		1024

static int 
read_cpu_fields (FILE *fp, unsigned long long int *fields)
{
	int retval;
	char buffer[BUF_MAX] = {0};


	if (!fgets (buffer, BUF_MAX, fp)) { 
	 return 0;
	}
  	debug (LOG_DEBUG, "/proc/stat = %s",buffer);
	retval = sscanf (buffer, "cpu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu", 
							&fields[0], 
							&fields[1], 
							&fields[2], 
							&fields[3], 
							&fields[4], 
							&fields[5], 
							&fields[6], 
							&fields[7], 
							&fields[8], 
							&fields[9]); 
	if (retval < 4) { /* Atleast 4 fields is to be read */
		return 0;
	}

	return 1;
}

float
get_cpu_usage()
{
	FILE *fp;
	unsigned long long int fields[10], total_tick, total_tick_old, idle, idle_old, del_total_tick, del_idle;
	int i;
	double percent_usage;

	fp = fopen ("/proc/stat", "r");
	if (fp == NULL) {
		return 0.f;	
	}

	if (!read_cpu_fields (fp, fields)) { 
		fclose (fp);
		return 0.f; 
	}

	for (i=0, total_tick = 0; i<10; i++) { 
		total_tick += fields[i]; 
	}
	idle = fields[3]; /* idle ticks index */

	total_tick_old = total_tick;
	idle_old = idle;

	s_sleep(1, 0);
	fseek (fp, 0, SEEK_SET);
	fflush (fp);
	if (!read_cpu_fields (fp, fields)){ 
		fclose (fp);
		return 0.f; 
	}

	for (i=0, total_tick = 0; i<10; i++) { 
//    	debug (LOG_DEBUG, "Total CPU Usage %d = %llu , %llu", i, total_tick,fields[i]);
		total_tick += fields[i]; 
	}
	idle = fields[3];

	del_total_tick = total_tick - total_tick_old;
	del_idle = idle - idle_old;

	percent_usage = ((del_total_tick - del_idle) / (float) del_total_tick) * 100; /* 3 is index of idle time */
	if (del_total_tick>0)
  	  debug (LOG_DEBUG, "CPU使用率：%3.2lf%%", percent_usage);
    else
  	  debug (LOG_DEBUG, "CPU使用情况，总数：(%ld-%ld), 空闲：(%ld-%ld)", total_tick_old,total_tick,idle_old,idle);
	fclose (fp); 

	return percent_usage;
}

// s_sleep using select timeout method to instead of sleep-func
// s: second, u: usec 10^6usec = 1s
void 
s_sleep(unsigned int s, unsigned int u){
	struct timeval timeout;
	timeout.tv_sec = s;
	timeout.tv_usec = u;

	select(0, NULL, NULL, NULL, &timeout);
}

void gettimestr(time_t ts,char *str_text,int len)
{
    struct tm *my_tm;
    my_tm = localtime(&ts);
    snprintf(str_text, len, "%d-%02d-%02d %02d:%02d:%02d",1900 + my_tm->tm_year, 1 + my_tm->tm_mon, my_tm->tm_mday,my_tm->tm_hour, my_tm->tm_min, my_tm->tm_sec);
}

void trim(char* s, char c)
{
    char *t=s;
    while (*s == c){
		s++;
	}
    while (*s && *s != c){
		*t=*s;
		s++;
		t++;
	}
	*t=0;
}

char * gettimeofdaystr(char *out_text,size_t out_len)
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    snprintf(out_text,out_len,"%ld%ld",tv.tv_sec,tv.tv_usec);
	return out_text;
}


char * getwanaddr(char *out_text,size_t out_len)
{
    char cmd[256] = {0};
    FILE *f_dhcp = NULL;
     
    snprintf(cmd, 256, "ifconfig eth1|grep \"inet addr\"|cut -d':' -f 2|cut -d' ' -f 0");    
    
    debug(LOG_DEBUG, "分析/etc/confg/network文件得到wan的IP地址，执行命令：%s", cmd);
    if((f_dhcp = popen(cmd, "r")) != NULL) {
        char name[32] = {0};
        fgets(name, 31,  f_dhcp);
        pclose(f_dhcp);
	    if(name&&name[strlen(name)-1] == '\n')
		    name[strlen(name)-1] = '\0';
		strncpy(out_text,name,out_len);
        debug(LOG_DEBUG, "得到路由器的外部IP地址：%s", out_text);
    }
	return out_text;
}