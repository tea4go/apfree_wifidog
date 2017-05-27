/* vim: set et sw=4 ts=4 sts=4 : */
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

/* $Id$ */
/** @file https_server.c
  @brief 
  @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
  */

#include "https_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#ifndef S_ISDIR
#define S_ISDIR(x) (((x) & S_IFMT) == S_IFDIR)
#endif
#else
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/time.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#ifdef EVENT__HAVE_NETINET_IN_H
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#endif

#ifdef _WIN32
#define stat _stat
#define fstat _fstat
#define open _open
#define close _close
#define O_RDONLY _O_RDONLY
#endif

#include <syslog.h>

#include "https_server.h"
#include "debug.h"
#include "conf.h"
#include "gateway.h"
#include "wd_util.h"
#include "util.h"
#include "firewall.h"
#include "safe.h"

static struct event_base *base		= NULL;
static struct evdns_base *dnsbase 	= NULL;

static void check_internet_available_cb(int errcode, struct evutil_addrinfo *addr, void *ptr);

// !!!remember to free the return url
char *
evhttp_get_request_url(struct evhttp_request *req) {
	char url[256] = {0}; // only get 256 char from request url
	
	snprintf(url, 256, "https://%s%s",
		evhttp_request_get_host(req),
		evhttp_request_get_uri(req));
	
	return evhttp_encode_uri(url);
}

// !!!remember to free the return redir_url
char *
evhttpd_get_full_redir_url(const char *mac, const char *ip, const char *orig_url) {
	struct evbuffer *evb = evbuffer_new();
	s_config *config = config_get_config();
	char *protocol = NULL;
    int port = 80;
	char time_str[64];
    t_auth_serv *auth_server = get_auth_server();

    if (auth_server->authserv_use_ssl) {
        protocol = "https";
        port = auth_server->authserv_ssl_port;
    } else {
        protocol = "http";
        port = auth_server->authserv_http_port;
    }
	
	evbuffer_add_printf(evb, "%s://%s:%d%s%sgw_address=%s&gw_port=%d&gw_id=%s&channel_path=%s&ssid=%s&ip=%s&mac=%s&url=%s&call_counter=%s",
					protocol, auth_server->authserv_hostname, port, auth_server->authserv_path,
					auth_server->authserv_login_script_path_fragment,
					config->gw_address, config->gw_port, config->gw_id, 
					g_channel_path?g_channel_path:"null",
					g_ssid?g_ssid:"null",
					ip, mac, orig_url, gettimeofdaystr(time_str,sizeof(time_str)));
	
	char *redir_url = evb_2_string(evb, NULL);
    //debug (LOG_DEBUG, "evhttpd_get_full_redir_url() : 获取重定向地址：%s",redir_url);
	evbuffer_free(evb);
	
	return redir_url;
}

void
evhttpd_gw_reply(struct evhttp_request *req, struct evbuffer *data_buffer) {
	struct evbuffer *evb = evbuffer_new();
	int len 	= 0;
	char *data	= evb_2_string(data_buffer, &len);
	evbuffer_add(evb, data, len);
	
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Content-Type", "text/html");
	evhttp_send_reply (req, 200, "OK", evb); 	
	evbuffer_free(evb);
}

void
evhttp_gw_reply_js_redirect(struct evhttp_request *req, const char *peer_addr,char *req_url) {
	char *mac = (char *)arp_get(peer_addr);
	char *redir_url = evhttpd_get_full_redir_url(mac!=NULL?mac:"ff:ff:ff:ff:ff:ff", peer_addr, req_url);
	struct evbuffer *evb = evbuffer_new();
	struct evbuffer *evb_redir_url = evbuffer_new();	                  
	
    //#define    WIFIDOG_REDIR_HTML_CONTENT    "setTimeout(function() {location.href = \"%s\";}, 10);"
	debug (LOG_INFO, "https_callback_404() : 捕获 %s 请求 [%s]==>[%s]", peer_addr, req_url,redir_url);
	evbuffer_add(evb, wifidog_redir_html->front, wifidog_redir_html->front_len);
	evbuffer_add_printf(evb_redir_url, WIFIDOG_REDIR_HTML_CONTENT, redir_url, 10);
	evbuffer_add_buffer(evb, evb_redir_url);
	evbuffer_add(evb, wifidog_redir_html->rear, wifidog_redir_html->rear_len);
	
	evhttp_add_header(evhttp_request_get_output_headers(req),"Content-Type", "text/html");
	evhttp_send_reply (req, 200, "OK", evb); 
	
	free(mac);
	free(redir_url);
	evbuffer_free(evb);
	evbuffer_free(evb_redir_url);
}

static void
process_https_cb (struct evhttp_request *req, void *arg) {  			
	/* Determine peer */
	char *peer_addr;
	ev_uint16_t peer_port;
	struct evhttp_connection *con = evhttp_request_get_connection (req);
	evhttp_connection_get_peer (con, &peer_addr, &peer_port);
	char *tmp_url = evhttp_get_request_url(req); 
	
	if ( strstr(tmp_url,"wowenda") ||
		 strstr(tmp_url,"duba") ||
		 strstr(tmp_url,"kcs") ||
		 strstr(tmp_url,"kns") ||
		 strstr(tmp_url,"firefox") ||
		 strstr(tmp_url,"wps") ||
		 strstr(tmp_url,"qq") ||
		 strstr(tmp_url,"pc120") ||
		 strstr(tmp_url,"symcd") ||
		 strstr(tmp_url,"query3") ||		
		 strstr(tmp_url,"microsoft") ||			
		 strstr(tmp_url,"180.163.25.38") ||	
		 strstr(tmp_url,"114.112.67.221") ||	
		 strstr(tmp_url,"120.92.32.253") ||	
		 strstr(tmp_url,"112.90.139.96") ||			
		 strstr(tmp_url,"suggestion.baidu.com") ||			
 		 strstr(tmp_url,"ijinshan") ) {
		//printf("无效的网页访问，%s\n",tmp_url);
		free(tmp_url);
		return;
	}

	if (!is_online()) {    
        debug(LOG_DEBUG, "https_callback_404() : 网关服务器不在线，返回不在线页面。捕获 %s 请求 [%s]", peer_addr?peer_addr:"空",tmp_url);
		evhttpd_gw_reply(req, evb_internet_offline_page);
    } else if (!is_auth_online()) {  
        debug(LOG_DEBUG, "https_callback_404() : Auth服务器不在线，返回不在线页面。捕获 %s 请求 [%s]", peer_addr?peer_addr:"空",tmp_url);
		evhttpd_gw_reply(req, evb_authserver_offline_page);
    } else {
		evhttp_gw_reply_js_redirect(req, peer_addr,tmp_url);
	}

	free(tmp_url);
	//debug(LOG_DEBUG, "https_callback_404() : end");
}

/**
 * This callback is responsible for creating a new SSL connection
 * and wrapping it in an OpenSSL bufferevent.  This is the way
 * we implement an https server instead of a plain old http server.
 */
static struct bufferevent* bevcb (struct event_base *base, void *arg) { 
	struct bufferevent* r;
  	SSL_CTX *ctx = (SSL_CTX *) arg;

  	r = bufferevent_openssl_socket_new (base,
                                      -1,
                                      SSL_new (ctx),
                                      BUFFEREVENT_SSL_ACCEPTING,
                                      BEV_OPT_CLOSE_ON_FREE);
  	return r;
}

static void server_setup_certs (SSL_CTX *ctx,
                                const char *certificate_chain,
                                const char *private_key) { 
  	if (1 != SSL_CTX_use_certificate_chain_file (ctx, certificate_chain))
    	die_most_horribly_from_openssl_error ("SSL_CTX_use_certificate_chain_file");

  	if (1 != SSL_CTX_use_PrivateKey_file (ctx, private_key, SSL_FILETYPE_PEM))
    	die_most_horribly_from_openssl_error ("SSL_CTX_use_PrivateKey_file");

  	if (1 != SSL_CTX_check_private_key (ctx))
    	die_most_horribly_from_openssl_error ("SSL_CTX_check_private_key");
}

static void check_internet_available(t_popular_server *popular_server) {
	if (!popular_server)
		return;

    debug(LOG_DEBUG, "check_internet_available()");
	mark_offline();

	struct evutil_addrinfo hints;
	memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = EVUTIL_AI_CANONNAME;//http://www.360doc.com/content/14/0102/10/15064667_341888075.shtml
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
	
    debug(LOG_DEBUG, "check_internet_available() : 解析互联网地址(%s)",popular_server->hostname);	
	evdns_getaddrinfo( dnsbase, popular_server->hostname, NULL ,
          &hints, check_internet_available_cb, popular_server);
    debug(LOG_DEBUG, "check_internet_available() : end");	
}

static void check_internet_available_cb(int errcode, struct evutil_addrinfo *addr, void *ptr) {
    debug (LOG_DEBUG, "check_internet_available(回调函数)");
	if (errcode) { 
		t_popular_server *popular_server = ptr;
		if (popular_server) {
            debug (LOG_DEBUG, "check_internet_available(回调函数) : DNS查询出错，将解析下一个域名。URL=%s，错误：%s", popular_server->hostname, evutil_gai_strerror(errcode));
			check_internet_available(popular_server->next);
        }
	} else {
		if (addr) {
			// popular server dns resolve success
			debug (LOG_DEBUG, "check_internet_available(回调函数) : 互联网可用，网关服务器标为在线。");
			mark_online();
			evutil_freeaddrinfo(addr);
		}
	}
    debug (LOG_DEBUG, "check_internet_available(回调函数) : end");
}

static void check_auth_server_available_cb(int errcode, struct evutil_addrinfo *addr, void *ptr) {
    debug (LOG_DEBUG, "check_authserver_available(回调函数)");
	t_auth_serv *auth_server = (t_auth_serv *)ptr;
	if (errcode) { 
		if (auth_server && auth_server->last_ip)
          debug (LOG_DEBUG, "check_authserver_available(回调函数) : DNS查询出错，IP地址：%s，错误：%s", auth_server->last_ip,evutil_gai_strerror(errcode));		
		else
          debug (LOG_DEBUG, "check_authserver_available(回调函数) : DNS查询出错，错误：%s", evutil_gai_strerror(errcode));
		mark_auth_offline();
		mark_auth_server_bad(auth_server);
	} else {
		int i = 0;
		if (!addr) {
			debug (LOG_ERR, "不可能，回调函数传入的addr为空。");
			return;
		}
		for (;addr; addr = addr->ai_next, i++) 
		{
			char ip[128] = {0};
			if (addr->ai_family == PF_INET) {
				struct sockaddr_in *sin = (struct sockaddr_in*)addr->ai_addr;
            	evutil_inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip)-1);

            	if (!auth_server->last_ip || strcmp(auth_server->last_ip, ip) != 0) 
				{
                    debug (LOG_DEBUG, "check_authserver_available(回调函数) : 更新Auth服务器 %s 的IP地址(%s)",auth_server->authserv_hostname, ip);
		            if (auth_server->last_ip)
		                free(auth_server->last_ip);
		            auth_server->last_ip = safe_strdup(ip);

					/* Update firewall rules */
					debug (LOG_DEBUG, "check_authserver_available(回调函数) : 清除Auth服务器的防火墙规则。");
		            fw_clear_authservers();

					debug (LOG_DEBUG, "check_authserver_available(回调函数) : 设置Auth服务器的防火墙规则。");
		            fw_set_authservers();

		            evutil_freeaddrinfo(addr);
		            break;
		        } else{
                    debug (LOG_DEBUG, "check_authserver_available(回调函数) : Auth服务器 %s 的IP地址(%s)没有变化，不需要更新。",auth_server->authserv_hostname, ip);
				}
			}
		}
	}
    debug (LOG_DEBUG, "check_authserver_available(回调函数) : end");
}

static void check_auth_server_available() {
    debug(LOG_DEBUG, "check_authserver_available()");


	s_config *config = config_get_config();
    t_auth_serv *auth_server = config->auth_servers;
    struct evutil_addrinfo hints;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = EVUTIL_AI_CANONNAME;

    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    debug(LOG_DEBUG, "check_authserver_available() : 解析Auth服务器域名(%s)",auth_server->authserv_hostname);
    evdns_getaddrinfo( dnsbase, auth_server->authserv_hostname, NULL ,
              &hints, check_auth_server_available_cb, auth_server);

    debug(LOG_DEBUG, "check_authserver_available() : end");
}

static void schedule_work_cb(evutil_socket_t fd, short event, void *arg) {
	struct event *timeout = (struct event *)arg;
	struct timeval tv;
	static long update_domain_interval = 1;

    debug(LOG_DEBUG, "schedule_work_cb()");

    debug(LOG_DEBUG, "schedule_work_cb() : 检测互联网状态。");
	t_popular_server *popular_server = config_get_config()->popular_servers;
	check_internet_available(popular_server);

    debug(LOG_DEBUG, "schedule_work_cb() : 检测Auth服务器状态。");
	check_auth_server_available();
	
	// if config->update_domain_interval not 0
	if (update_domain_interval == config_get_config()->update_domain_interval) {	
        debug(LOG_DEBUG, "schedule_work_cb() : 解析内置白名单。");
		parse_inner_trusted_domain_list();

		debug(LOG_DEBUG, "schedule_work_cb() : 设置内置白名单的防火墙规则。");
		fw_refresh_inner_domains_trusted();

		debug(LOG_DEBUG, "schedule_work_cb() : 解析用户白名单。");
		parse_user_trusted_domain_list();
		debug(LOG_DEBUG, "schedule_work_cb() : 设置用户白名单的防火墙规则。");
		fw_refresh_user_domains_trusted();

		update_domain_interval = 1;
	} else
		update_domain_interval++;

    //因为前面注册事件时是这个 EV_PERSIST,永久性事情。
	evutil_timerclear(&tv);
	tv.tv_sec = config_get_config()->checkinterval+7;
	event_add(timeout, &tv);
    debug(LOG_DEBUG, "schedule_work_cb() : end");
}

static int https_redirect (char *gw_ip,  t_https_server *https_server) { 	
    debug(LOG_DEBUG, "thread_https_server()");
  	struct evhttp *http;
  	struct evhttp_bound_socket *handle;
	struct event timeout;
	struct timeval tv;
	
    debug(LOG_DEBUG, "thread_https_server() : 执行初始化libevent库。");
  	base = event_base_new();
  	if (! base) { 
		debug (LOG_ERR, "执行event_base_new函数出错。");
      	return 1;
    }
	
  	/* Create a new evhttp object to handle requests. */
  	http = evhttp_new(base);
  	if (! http) { 
		debug (LOG_ERR, "执行evhttp_new函数出错。");
        event_base_free(base);
      	return 1;
    }
 
 	SSL_CTX *ctx = SSL_CTX_new (SSLv23_server_method());
	if (!ctx) {
        debug(LOG_ERR, "执行SSL_CTX_new函数出错。");
		evhttp_free(http);
        event_base_free(base);
      	return 1;
	}

  	SSL_CTX_set_options(ctx,
                       SSL_OP_SINGLE_DH_USE |
                       SSL_OP_SINGLE_ECDH_USE |
                       SSL_OP_NO_SSLv2);

	/* Cheesily pick an elliptic curve to use with elliptic curve ciphersuites.
	* We just hardcode a single curve which is reasonably decent.
	* See http://www.mail-archive.com/openssl-dev@openssl.org/msg30957.html */
	EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (! ecdh){
        debug(LOG_ERR, "执行EC_KEY_new_by_curve_name函数出错，进程将退出。");
		SSL_CTX_free(ctx);
		evhttp_free(http);
        event_base_free(base);
      	exit(EXIT_FAILURE);
	}

  	if (1 != SSL_CTX_set_tmp_ecdh(ctx, ecdh)){
        debug(LOG_ERR, "执行SSL_CTX_set_tmp_ecdh函数出错，进程将退出。");
		SSL_CTX_free(ctx);
		evhttp_free(http);
        event_base_free(base);
      	exit(EXIT_FAILURE);
	}

    debug(LOG_DEBUG, "thread_https_server() : 设置HTTPs的证书。Pem=%s，Key=%s",https_server->svr_crt_file, https_server->svr_key_file);
	server_setup_certs(ctx, https_server->svr_crt_file, https_server->svr_key_file);

	/* This is the magic that lets evhttp use SSL. */
	evhttp_set_bevcb (http, bevcb, ctx);
 
	/* This is the callback that gets called when a request comes in. */
    debug(LOG_DEBUG, "thread_https_server() : 注册HTTPs服务器的收到请求的回调函数。");
	evhttp_set_gencb (http, process_https_cb, NULL);

	/* Now we tell the evhttp what port to listen on */
    debug(LOG_DEBUG, "thread_https_server() : 注册HTTPs服务器监听端口(%s:%d)",gw_ip,https_server->gw_https_port);
	handle = evhttp_bind_socket_with_handle (http, gw_ip, https_server->gw_https_port);
	if (! handle) { 
		debug (LOG_ERR, "不能注册HTTPs服务器监听端口(%s:%d)",gw_ip,(int) https_server->gw_https_port);
		SSL_CTX_free(ctx);
		evhttp_free(http);
        event_base_free(base);
		return 1;
    }
    
	// check whether internet available or not(检查互联网是否可用)
    debug(LOG_DEBUG, "thread_https_server() : 获得DNS服务器地址(/tmp/resolv.conf.auto)");

	//evdns_base_new函数，如果initialize参数设置为1,则使用操作系统的默认配置.如果为0,则不设置域名解析服务器和配置参数.  
	//可以使用evdns_base_resolv_conf_parse()函数来读取一个配置文件,实现自定义配置,这里就不多说了.  
	dnsbase = evdns_base_new(base, 0);
	if ( 0 != evdns_base_resolv_conf_parse(dnsbase, DNS_OPTION_NAMESERVERS, "/tmp/resolv.conf.auto") ) {
        debug(LOG_ERR, "执行evdns_base_resolv_conf_parse函数出错，读取一个配置文件(/tmp/resolv.conf.auto)");
		evdns_base_free(dnsbase, 0);
		dnsbase = evdns_base_new(base, 1);
	}
	evdns_base_set_option(dnsbase, "timeout", "0.2");
	
	t_popular_server *popular_server = config_get_config()->popular_servers;

    debug(LOG_DEBUG, "thread_https_server() : 检测互联网连接状态，通过解析(%s)域名地址来判断。",popular_server->hostname);
	check_internet_available(popular_server);

    debug(LOG_DEBUG, "thread_https_server() : 检测Auth服务器状态。");
    debug(LOG_DEBUG, "thread_https_server() : 注意：1、此处只解析Auth服务器的域名，更新为IP地址。");
    debug(LOG_DEBUG, "thread_https_server() :       2、标记Auth服务器是否在线，是通过调用Auth服务器的/ping调用来完成)");
	check_auth_server_available();

    //int event_assign(struct event *, struct event_base *, evutil_socket_t fd, short flag, event_callback_fn func_name, void * arg);
	//fd   需要监视文件描述符,当fd=-1时，事件被手动激活或者定时器溢出激活
    //flag EV_PERSIST 表示事件是“持久的”
    //flag 0          表示 ”
	//func_name 回调函数，它有三个参数(vent_assign的fd, event和arg；arg：传递给cb函数指针的参数)
	//arg  传给回调函数的参数
    debug(LOG_DEBUG, "thread_https_server() : 注册定时任务事件，间隔%d秒，定时检测Auth服务器状态。",config_get_config()->checkinterval+7);
	event_assign(&timeout, base, -1, 0, schedule_work_cb, (void*) &timeout);
	evutil_timerclear(&tv);         
	tv.tv_sec = config_get_config()->checkinterval+7;
	//激活该事件
    event_add(&timeout, &tv);

	
	//调用该函数会一直阻塞在这里，等待时间的触发。与event_base_loop等价。
    debug(LOG_DEBUG, "thread_https_server() : 一直阻塞在这里，等待网络请求。");
    event_base_dispatch(base);

    debug(LOG_DEBUG, "thread_https_server() : 释放分配的资源。");
	event_del(&timeout);
    evhttp_del_accept_socket(http, handle);
	SSL_CTX_free(ctx);
	evhttp_free(http);
    event_base_free(base);
	evdns_base_free(dnsbase, 0);

    debug(LOG_DEBUG, "thread_https_server() : end");
  	/* 不可能执行到这里，永远运行 */
  	return 0;
}

void thread_https_server(void *args) {
	s_config *config = config_get_config();
   	https_redirect (config->gw_address, config->https_server);
}
