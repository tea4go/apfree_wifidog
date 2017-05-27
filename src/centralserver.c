 /* vim: set sw=4 ts=4 sts=4 et : */
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
/** @file centralserver.c
  @brief Functions to talk to the central server (auth/send stats/get rules/etc...)
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>

#include "httpd.h"

#include "common.h"
#include "safe.h"
#include "util.h"
#include "wd_util.h"
#include "auth.h"
#include "conf.h"
#include "centralserver.h"
#include "firewall.h"
#include "version.h"
#include "debug.h"
#include "simple_http.h"
#include "http.h"

json_object *
auth_server_roam_request(const char *mac)
{
    s_config *config = config_get_config();
    int sockfd;
    char buf[MAX_BUF];
    char *tmp = NULL, *end = NULL;
    t_auth_serv *auth_server = NULL;
    auth_server = get_auth_server();


    sockfd = connect_auth_server();
    if (sockfd <= 0) {
        debug(LOG_ERR, "There was a problem connecting to the auth server!");        
        return NULL;
    }

     /**
     * TODO: XXX change the PHP so we can harmonize stage as request_type
     * everywhere.
     */
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf),
        "GET %sroam?gw_id=%s&mac=%s&channel_path=%s HTTP/1.1\r\n"
        "User-Agent: WiFi Firewall %s\r\n"
        "Connection: keep-alive\r\n"
        "Host: %s\r\n"
        "\r\n",
        auth_server->authserv_path,
        config->gw_id,
        mac,
        g_channel_path?g_channel_path:"null",
        VERSION, auth_server->authserv_hostname);

    char *res = http_get_ex(sockfd, buf, 2);

    close_auth_server();
    if (NULL == res) {
        debug(LOG_ERR, "There was a problem talking to the auth server!");        
        return NULL;
    }

    if ((tmp = strstr(res, "{\"")) && (end = strrchr(res, '}'))) {
        char *is_roam = NULL;
        *(end+1) = '\0';
        debug(LOG_DEBUG, "tmp is [%s]", tmp);
        json_object *roam_info = json_tokener_parse(tmp);
        if(roam_info == NULL) {
            debug(LOG_ERR, "error parse json info %s!", tmp);
            free(res);
            return NULL;
        }
    
        is_roam = json_object_get_string(json_object_object_get(roam_info, "roam"));
        if(is_roam && strcmp(is_roam, "yes") == 0) {
            json_object *client = json_object_object_get(roam_info, "client");
            if(client != NULL) {
                json_object *client_dup = json_tokener_parse(json_object_to_json_string(client));
                debug(LOG_INFO, "roam client is %s!", json_object_to_json_string(client));
                free(res);
                json_object_put(roam_info);
                return client_dup;
            }
        }

        free(res);
        json_object_put(roam_info);
        return NULL;
    }

    free(res);
    return NULL;
}

char * 
get_auth_uri(const char *request_type, client_type_t type, void *data)
{
    debug(LOG_DEBUG, "get_auth_uri()");
	if (data==NULL)
	{
        debug(LOG_ERR, "get_auth_uri() : 不可能，传入的client指针为空。");
        debug(LOG_DEBUG, "get_auth_uri() : end");
		return NULL;
	}

    char *ip    = NULL;
    char *mac   = NULL;
    char *name  = NULL;
    char *safe_token    = NULL;
    unsigned long long int incoming = 0,  outgoing = 0, incoming_delta = 0, outgoing_delta = 0;
    time_t first_login = 0;
    unsigned int online_time = 0;
    int wired = 0;
	char time_str[64];    


    switch(type) {
    case online_client:
    {
        t_client *o_client = (t_client *)data;
        ip  = o_client->ip;
        mac = o_client->mac;
        safe_token = httpdUrlEncode(o_client->token);
        if (o_client->name)
            name = o_client->name;
        first_login = o_client->first_login;
        incoming = o_client->counters.incoming;
        outgoing = o_client->counters.outgoing;
        incoming_delta  = o_client->counters.incoming_delta;
        outgoing_delta  = o_client->counters.outgoing_delta;
        break;
    }
        
    case trusted_client:
    {
        t_trusted_mac *t_mac = (t_trusted_mac *)data;
        ip  = t_mac->ip;
        mac = t_mac->mac;
        wired = 0;//is_device_wired(mac);
        break;
    }

    default:
        debug(LOG_DEBUG, "get_auth_uri() : end");
        return NULL;
    }

    s_config *config = config_get_config();
    t_auth_serv *auth_server = get_auth_server();
    char *uri = NULL;
    int nret = 0;

    if (config->deltatraffic) {
        nret = safe_asprintf(&uri, 
             "%s%sstage=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&incomingdelta=%llu&outgoingdelta=%llu&first_login=%lld&online_time=%u&gw_id=%s&channel_path=%s&name=%s&wired=%d&call_counter=%s",
             auth_server->authserv_path,
             auth_server->authserv_auth_script_path_fragment,
             request_type,
             ip, mac, safe_token, 
             incoming, 
             outgoing, 
             incoming_delta, 
             outgoing_delta,
             (long long)first_login,
             online_time,
             config->gw_id,
             g_channel_path?g_channel_path:"null", 
             name?name:"null", wired, gettimeofdaystr(time_str,sizeof(time_str)));
    } else {
        nret = safe_asprintf(&uri, 
             "%s%sstage=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&first_login=%lld&online_time=%u&gw_id=%s&channel_path=%s&name=%s&wired=%d&call_counter=%s",
             auth_server->authserv_path,
             auth_server->authserv_auth_script_path_fragment,
             request_type,
             ip, mac, safe_token, 
             incoming, 
             outgoing, 
             (long long)first_login,
             online_time,
             config->gw_id,
             g_channel_path?g_channel_path:"null", 
             name?name:"null", wired, gettimeofdaystr(time_str,sizeof(time_str)));
    }

    if (safe_token) 
		free(safe_token);

	if (nret>0)
	{
	    debug(LOG_DEBUG, "get_auth_uri() : 获得请求Auth服务器的地址：%s",uri);
	}

    debug(LOG_DEBUG, "get_auth_uri() : end");
    return nret>0?uri:NULL;
}

/** 启动与验证服务器的交易，以进行身份验证或更新服务器上的流量计数器
 * Initiates a transaction with the auth server, either to authenticate or to
 * update the traffic counters at the server
@param authresponse Returns the information given by the central server 
@param request_type Use the REQUEST_TYPE_* defines in centralserver.h
@param ip IP adress of the client this request is related to
@param mac MAC adress of the client this request is related to
@param token Authentification token of the client
@param incoming Current counter of the client's total incoming traffic, in bytes 
@param outgoing Current counter of the client's total outgoing traffic, in bytes 
*/
t_authcode
auth_server_request(t_authresponse * authresponse, const char *request_type, const char *ip, const char *mac,
                    const char *token, unsigned long long int incoming, unsigned long long int outgoing, 
                    unsigned long long int incoming_delta, unsigned long long int outgoing_delta,
                    time_t first_login, unsigned int online_time, char *name, int wired)
{
    debug(LOG_DEBUG, "call_counters() : %s",request_type);
    s_config *config = config_get_config();
    int sockfd;
    char buf[MAX_BUF] = {0};
    char *tmp;
    char *safe_token;
	char time_str[64];
    t_auth_serv *auth_server = get_auth_server();

    /* Blanket default is error. */
    authresponse->authcode = AUTH_ERROR;

	//增加逻辑 By LiuQiQuan
	//这里需要判断是否为HTTPs的Auth服务器。如果HTTPs服务器是否不需要连接，还没有试。******严重问题********
	if (!auth_server->authserv_use_ssl)
	{
		debug(LOG_DEBUG, "call_counters() : %s (连接Auth服务器)",request_type);
		sockfd = connect_auth_server();
		if (sockfd <= 0) {
			debug(LOG_ERR, "连接到验证服务器时出现问题！");        
			return AUTH_ERROR;
		}
	}
    /**
     * TODO: XXX change the PHP so we can harmonize stage as request_type
     * everywhere.
     */
    safe_token = httpdUrlEncode(token);
    if(config -> deltatraffic) {
           snprintf(buf, (sizeof(buf) - 1),
             "GET %s%sstage=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&incomingdelta=%llu&outgoingdelta=%llu&first_login=%lld&online_time=%u&gw_id=%s&channel_path=%s&name=%s&wired=%d&call_counter=%s HTTP/1.1\r\n"
             "User-Agent: WiFi Firewall %s\r\n"
             "Connection: keep-alive\r\n"
             "Host: %s\r\n"
             "\r\n",
             auth_server->authserv_path,
             auth_server->authserv_auth_script_path_fragment,
             request_type,
             ip, mac, safe_token, 
             incoming, 
             outgoing, 
             incoming_delta, 
             outgoing_delta,
             (long long)first_login,
             online_time,
             config->gw_id,
             g_channel_path?g_channel_path:"null", 
             name?name:"null",
             wired,gettimeofdaystr(time_str,sizeof(time_str)),
             VERSION, auth_server->authserv_hostname);
    } else {
            snprintf(buf, (sizeof(buf) - 1),
             "GET %s%sstage=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&first_login=%lld&online_time=%u&gw_id=%s&channel_path=%s&name=%s&wired=%d&call_counter=%s HTTP/1.1\r\n"
             "User-Agent: WiFi Firewall %s\r\n"
             "Connection: keep-alive\r\n"
             "Host: %s\r\n"
             "\r\n",
             auth_server->authserv_path,
             auth_server->authserv_auth_script_path_fragment,
             request_type,
             ip,
             mac, safe_token, incoming, outgoing, 
             (long long)first_login, online_time,
             config->gw_id, 
             g_channel_path?g_channel_path:"null",
             name,
             wired,gettimeofdaystr(time_str,sizeof(time_str)),
             VERSION, auth_server->authserv_hostname);
        }
    free(safe_token);

    debug(LOG_DEBUG, "call_counters() : %s (请求Auth服务器/wifidog/auth)",request_type);
    char *res = http_get(sockfd, buf);
    if (NULL == res) {
        close_auth_server();
        debug(LOG_ERR, "请求Auth服务器时出现问题!");
        return (AUTH_ERROR);
    }

    debug(LOG_DEBUG, "call_counters() : %s (关闭Auth服务器连接)",request_type);
    decrease_authserv_fd_ref();
    if ((tmp = strstr(res, "Auth: "))) {
        if (sscanf(tmp, "Auth: %d", (int *)&authresponse->authcode) == 1) {
            debug(LOG_DEBUG, "call_counters() : 请求Auth服务器/wifidog/auth时返回验证码(%d)正确", authresponse->authcode);
            free(res);
            debug(LOG_DEBUG, "call_counters() : end");
            return (authresponse->authcode);
        } else {
            debug(LOG_WARNING, "请求Auth服务器/wifidog/auth时返回验证码(%d)错误", authresponse->authcode);
            free(res);
            debug(LOG_DEBUG, "call_counters() : end");
            return (AUTH_ERROR);
        }
    }
    free(res);

    debug(LOG_DEBUG, "call_counters() : end");
    return (AUTH_ERROR);
}

/* Tries really hard to connect to an auth server. Returns a file descriptor, -1 on error
 */
int
connect_auth_server()
{
    debug(LOG_DEBUG, "connect_auth_server()");
    int sockfd;

    LOCK_CONFIG();
    sockfd = _connect_auth_server(0);    
    UNLOCK_CONFIG();

    if (sockfd == -1) {
        debug(LOG_ERR, "没有连上Auth服务器");
        mark_auth_offline();
    } else {
        debug(LOG_DEBUG, "已连上Auth服务器");
        mark_auth_online();
    }

    debug(LOG_DEBUG, "connect_auth_server() : end");
    return (sockfd);
}

// just decrease authserv_fd_ref
void
decrease_authserv_fd_ref()
{
    s_config *config = config_get_config();
    t_auth_serv *auth_server = NULL;
    
    LOCK_CONFIG();

    for (auth_server = config->auth_servers; auth_server; auth_server = auth_server->next) {
        if (auth_server->authserv_fd > 0) {
            auth_server->authserv_fd_ref -= 1;
            if (auth_server->authserv_fd_ref == 0) {
                debug(LOG_DEBUG, "Auth服务器网络句柄引用次数：0，暂时不关闭网络连接。");
            } else if (auth_server->authserv_fd_ref < 0) {
                debug(LOG_ERR, "不可能，Auth服务器网络句柄引用次数：%d", auth_server->authserv_fd_ref);
                close(auth_server->authserv_fd);
                auth_server->authserv_fd = -1;
                auth_server->authserv_fd_ref = 0;
            }
        }
    }
    
    UNLOCK_CONFIG();
}

void
close_auth_server()
{
    LOCK_CONFIG();
    _close_auth_server();
    UNLOCK_CONFIG();
}

void
_close_auth_server()
{
    s_config *config = config_get_config();
    t_auth_serv *auth_server = NULL;
    
    for (auth_server = config->auth_servers; auth_server; auth_server = auth_server->next) {
        if (auth_server->authserv_fd > 0) {
            auth_server->authserv_fd_ref -= 1;
            if (auth_server->authserv_fd_ref <= 0) {
                debug(LOG_DEBUG, "直接关闭Auth服务器的网络连接。");
                close(auth_server->authserv_fd);
                auth_server->authserv_fd = -1;
                auth_server->authserv_fd_ref = 0;
            } 
        }
    }
}

/* Helper function called by connect_auth_server() to do the actual work including recursion
 * DO NOT CALL DIRECTLY
 @param level recursion level indicator must be 0 when not called by _connect_auth_server()
 */
int
_connect_auth_server(int level) {
    s_config *config = config_get_config();
    t_auth_serv *auth_server = NULL;
    struct in_addr *h_addr;
    int num_servers = 0;
    char *hostname = NULL;
    char *ip;
    struct sockaddr_in their_addr;
    int sockfd;

    /* If there are no auth servers, error out, from scan-build warning. */
    if (NULL == config->auth_servers) {
        return -1;
    }
    if (!is_online()) {
        debug(LOG_DEBUG, "connect_auth_server() : <%d>对不起，互联网不可用。",level);
        return -1;
    }
    
    auth_server = config->auth_servers;
    if (auth_server->authserv_fd > 0) {
        if (is_socket_valid(auth_server->authserv_fd)) {
            debug(LOG_DEBUG, "connect_auth_server() : <%d>使用keep-alive保持连接，目前网络句柄引用次数：%d", level,auth_server->authserv_fd_ref);
            auth_server->authserv_fd_ref++;
            return auth_server->authserv_fd;
        } else {
            debug(LOG_DEBUG, "connect_auth_server() : <%d>服务器已关闭此连接，将初始化它。",level);
            close(auth_server->authserv_fd);
            auth_server->authserv_fd = -1;
            auth_server->authserv_fd_ref = 0;
            return _connect_auth_server(level);
        }
    }
    
    /* XXX level starts out at 0 and gets incremented by every iterations. */
    level++;

	//增加逻辑 By LiuQiQuan
	//如果当前的Auth服务器是HTTPs类型，则直接退出，让上层的函数选择是否调evpings，还是ping。
	if (auth_server->authserv_use_ssl)
	{
        debug(LOG_DEBUG, "connect_auth_server() : <%d>当前Auth服务器(%s)为HTTPs，忽略本次连接。",level,auth_server->authserv_hostname);
		return -1;
	}

    /*
     * Let's calculate the number of servers we have
     */
    for (auth_server = config->auth_servers; auth_server; auth_server = auth_server->next) {
        num_servers++;
    }
    if (level > num_servers) {
        /*
         * We've called ourselves too many times
         * This means we've cycled through all the servers in the server list
         * at least once and none are accessible
         */
        return (-1);
    }    

    /*
     * Let's resolve the hostname of the top server to an IP address
     */
    auth_server = config->auth_servers;
    hostname = auth_server->authserv_hostname;
    debug(LOG_DEBUG, "connect_auth_server() : <%d>正在解析Auth服务器(%s)", level, hostname);
    h_addr = wd_gethostbyname(hostname);
    if (!h_addr) {
        /*
         * DNS resolving it failed
         */
        debug(LOG_ERR, "<%d>解析Auth服务器(%s)失败", level, hostname);

        if (auth_server->last_ip) {
            free(auth_server->last_ip);
            auth_server->last_ip = NULL;
        }
        mark_auth_server_bad(auth_server);
        return _connect_auth_server(level);
    } else {
        /*
         * DNS resolving was successful
         */
        ip = safe_malloc(HTTP_IP_ADDR_LEN);
        inet_ntop(AF_INET, h_addr, ip, HTTP_IP_ADDR_LEN);
        ip[HTTP_IP_ADDR_LEN-1] = '\0';
        debug(LOG_DEBUG, "connect_auth_server() : <%d>解析Auth服务器(%s)成功，IP地址为：%s", level, hostname, ip);

        if (!auth_server->last_ip || strcmp(auth_server->last_ip, ip) != 0) {
            /*
             * But the IP address is different from the last one we knew
             * Update it
             */
            debug(LOG_DEBUG, "connect_auth_server() : <%d>更新Auth服务器最新IP地址为%s", level, ip);
            if (auth_server->last_ip)
                free(auth_server->last_ip);
            auth_server->last_ip = ip;

            /* Update firewall rules */
            fw_clear_authservers();
            fw_set_authservers();
        } else {
            /*
             * IP is the same as last time
             */
            free(ip);
        }

        /*
         * Connect to it
         */
        debug(LOG_DEBUG, "connect_auth_server() : <%d>正在连接Auth服务器(%s:%d)", level, hostname, auth_server->authserv_http_port);
        int port = htons(auth_server->authserv_http_port);

        their_addr.sin_port = port;
        their_addr.sin_family = AF_INET;
        their_addr.sin_addr = *h_addr;
        memset(&(their_addr.sin_zero), '\0', sizeof(their_addr.sin_zero));
        free(h_addr);

        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            debug(LOG_WARNING, "创建网络连接失败，错误号：%d，原因：%s", errno,strerror(errno));
            return (-1);
        }

        int res = wd_connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr), auth_server->authserv_connect_timeout);
        if (res == 0) {
            // connect successly
            debug(LOG_DEBUG,"connect_auth_server() : <%d>连接Auth服务器成功",level);
            auth_server->authserv_fd = sockfd;
            auth_server->authserv_fd_ref++;
            return sockfd;
        } else {
            debug(LOG_DEBUG,"connect_auth_server() : <%d>连接Auth服务器(%s:%d)失败，标识Auth服务器离线。错误号：%d，原因：%s",
                level, hostname, ntohs(port), errno,  strerror(errno));
            close(sockfd);
            mark_auth_server_bad(auth_server);
            return _connect_auth_server(level); /* Yay recursion! */
        }
    }
}

// 0, failure; 1, success(LiuQiQuan 还没有修改完 )
static int
parse_auth_server_response(t_authresponse *authresponse, struct evhttp_request *req) {
    debug(LOG_DEBUG, "fw_counter(回调函数)");
    if (!authresponse)
        return 0;

    char buffer[MAX_BUF] = {0};

    if (req == NULL || (req && req->response_code != 200)) 
    {
        debug(LOG_ERR, "调用Auth服务器的/wifidog/auth时出现问题，返回码：%d",(req?req->response_code:-1));
        mark_auth_offline();

        if (req == NULL)
            debug(LOG_WARNING, "fw_counter(回调函数) : 请求返回数据为NULL，应该是超时返回。");
        else {
            char buffer[MAX_BUF] = {0};
  	        
			debug(LOG_DEBUG, "fw_counter(回调函数) : 取返回数据");
            int nread = evbuffer_remove(evhttp_request_get_input_buffer(req),buffer, MAX_BUF-1);
            
			debug(LOG_DEBUG, "fw_counter(回调函数) : 从Auth服务器读取 %d 字节。", nread);
            if (nread > 0)
		        debug(LOG_DEBUG, "fw_counter(回调函数) : 接收到Auth服务器返回数据[%s]", buffer);
        }
    	debug(LOG_DEBUG, "fw_counter(回调函数) : end");
        return 0;
    }
    
    char *tmp = NULL;

	debug(LOG_DEBUG, "fw_counter(回调函数) : 取返回数据，返回码：%d",req->response_code);
    int nread = evbuffer_remove(evhttp_request_get_input_buffer(req), buffer, MAX_BUF-1);

	debug(LOG_DEBUG, "fw_counter(回调函数) : 从Auth服务器读取 %d 字节。", nread);
    if (nread > 0)
        debug(LOG_DEBUG, "fw_counter(回调函数) : 接收到Auth服务器返回数据[%s]", buffer);
    
    if (nread <= 0) {
        debug(LOG_ERR, "从Auth服务器读取数据错误，错误码：%d，原因：%s", errno, strerror(errno));
        mark_auth_offline();
    } else if ((tmp = strstr(buffer, "Auth: "))) 
    {
        mark_auth_online();

        sscanf(tmp, "Auth: %d", (int *)&authresponse->authcode);
        if (authresponse->authcode == 1) {
            debug(LOG_INFO, "接收到Auth服务器返回码<1>访问已更改为允许, 表示通过验证。");
            return 1;
        }
    }

	debug(LOG_WARNING, "接收到Auth服务器返回码<%d>没有返回预期的验证码。",authresponse->authcode);
   	debug(LOG_DEBUG, "fw_counter(回调函数) : end");
    return 0;
}

static void
reply_counter_response(t_authresponse *authresponse, struct evhttps_request_context * context) {
    debug(LOG_DEBUG, "fw_counter(回调函数)");
	
    struct auth_response_client *authresponse_client = context->data;
    t_client    *p1 = authresponse_client->client;
    t_client *tmp_c = NULL;
    time_t current_time = time(NULL);
	char date_str[50];
    s_config *config = config_get_config();

    if (p1 == NULL) {
        debug(LOG_DEBUG, "fw_counter(回调函数) : 终端为空，也许是信任的Mac终端。");
        return;
    }

    if (p1->counters.last_updated + (config->checkinterval * config->clienttimeout) <= current_time) {
        /* Timing out user */
 	    gettimestr(p1->counters.last_updated,date_str,sizeof(date_str)-1);
        debug(LOG_DEBUG, "fw_counter(回调函数) : 终端(%s)超时%ld/%ld秒(最后更新:%s)，删除超时的终端并在防火墙中拒绝终端。",
                  p1->ip, current_time - p1->counters.last_updated,config->checkinterval * config->clienttimeout,date_str);

		LOCK_CLIENT_LIST();
        tmp_c = client_list_find_by_client(p1);
        if (NULL != tmp_c) {
            debug(LOG_DEBUG, "fw_counter(回调函数) : 注销终端(%s)",p1->ip);
            evhttps_logout_client(context, tmp_c);
        } else {
            debug(LOG_DEBUG, "fw_counter(回调函数) : 终端(%s)已被删除，不需要注销登陆",p1->ip);
        }
        UNLOCK_CLIENT_LIST();
    }else if (config->auth_servers != NULL && p1->is_online) {
         //增加逻辑 By LiuQiQuan    
         //上面两行增加判断，省得进去判断了。
         /*
          * This handles any change in the status this allows us
          * to change the status of a user while he's connected
          *
          * Only run if we have an auth server configured!
          */
        debug(LOG_DEBUG, "fw_counter(回调函数) : 在线终端(%s)验证Auth服务器返回值(%d)",p1->ip,authresponse->authcode);
        fw_client_process_from_authserver_response(authresponse, p1);
    }
}

static void
reply_login_response(t_authresponse *authresponse, struct evhttps_request_context *context) {
    debug(LOG_DEBUG, "fw_counter(回调函数)");
    struct auth_response_client *authresponse_client = context->data;
    t_client            *client     = authresponse_client->client;
    t_client            *tmp        = NULL;
    t_offline_client    *o_client   = NULL;
    request     *r = authresponse_client->req;
    char    *urlFragment = NULL;
    char    *token = NULL;
    httpVar *var = NULL;
    

    /* Users could try to log in(so there is a valid token in
     * request) even after they have logged in, try to deal with
     * this */
    if ((var = httpdGetVariableByName(r, "token")) != NULL) {
        token = safe_strdup(var->value);
    } else {
        token = safe_strdup(client->token);
    }

    LOCK_CLIENT_LIST();
    /* can't trust the client to still exist after n seconds have passed */
    tmp = client_list_find_by_client(client);
    if (NULL == tmp) {
        debug(LOG_ERR, "fw_counter(回调函数) : 不能找到终端 %s(%s)", client->ip, client->mac);

		UNLOCK_CLIENT_LIST();
        client_list_destroy(client);    /* Free the cloned client */
        free(token);
        return;
    }

    client_list_destroy(client);        /* Free the cloned client */
    client = tmp;
    if (strcmp(token, client->token) != 0) {
        debug(LOG_DEBUG, "fw_counter(回调函数) : 终端的令牌变化需要更新。");
        free(client->token);
        client->token = token;
    } else {
        free(token);
    }
    debug(LOG_DEBUG, "fw_counter(回调函数) : 终端  %s(%s) 的令牌：%s",client->ip, client->mac,client->token);    

    s_config    *config = config_get_config();
    t_auth_serv *auth_server = get_auth_server();

    switch (authresponse->authcode) {

    case AUTH_ERROR:
        /* Error talking to central server */
  	    debug(LOG_ERR, "终端 %s(%s) 从网关服务器得到错误的令牌，将删除终端。", client->ip,client->mac);

		client_list_delete(client); 
        UNLOCK_CLIENT_LIST();

        send_http_page(r, "错误", "我们没有从网关服务器得到有效数据。");
        break;

    case AUTH_DENIED:
        /* Central server said invalid token */
        debug(LOG_INFO,"终端 %s(%s) 拒绝从网关服务器得到的令牌，从防火墙中删除并将其重定向到拒绝的消息。",client->ip, client->mac);

		fw_deny(client);
        client_list_delete(client);
        UNLOCK_CLIENT_LIST();

        safe_asprintf(&urlFragment, "%smessage=%s",
                      auth_server->authserv_msg_script_path_fragment, GATEWAY_MESSAGE_DENIED);
        http_send_redirect_to_auth(r, urlFragment, "重定向到拒绝消息。");
        free(urlFragment);
        break;

    case AUTH_VALIDATION:
        UNLOCK_CLIENT_LIST();
        /* They just got validated for X minutes to check their email */
        debug(LOG_INFO, "终端 %s(%s) 正在确认网关服务器得到的令牌，添加到防火墙并重定向到激活消息。", client->ip, client->mac);
        fw_allow(client, FW_MARK_PROBATION);    

        safe_asprintf(&urlFragment, "%smessage=%s",
                      auth_server->authserv_msg_script_path_fragment, GATEWAY_MESSAGE_ACTIVATE_ACCOUNT);
        http_send_redirect_to_auth(r, urlFragment, "重定向到激活消息");
        free(urlFragment);
        break;

    case AUTH_ALLOWED:
        UNLOCK_CLIENT_LIST();
        /* Logged in successfully as a regular account */
        debug(LOG_INFO, "终端 %s(%s) 从网关服务器得到的令牌有效，添加到防火墙并将其重定向到主页门户。",client->ip, client->mac);
        fw_allow(client, FW_MARK_KNOWN);
        
        //>>> liudf added 20160112
        client->first_login = time(NULL);
        client->is_online = 1;

        LOCK_OFFLINE_CLIENT_LIST();
        o_client = offline_client_list_find_by_mac(client->mac);    
        if(o_client)
            offline_client_list_delete(o_client);
        UNLOCK_OFFLINE_CLIENT_LIST();

        //<<< liudf added end
        served_this_session++;
        if(httpdGetVariableByName(r, "type")) {
            send_http_page_direct(r, "<html><body>微信授权成功！</body><html>");
        } else {
            safe_asprintf(&urlFragment, "%sgw_id=%s&channel_path=%s&mac=%s&name=%s", 
                auth_server->authserv_portal_script_path_fragment, 
                config->gw_id,
                g_channel_path?g_channel_path:"null",
                client->mac?client->mac:"null",
                client->name?client->name:"null");
            http_send_redirect_to_auth(r, urlFragment, "重定向到主页门户。");
            free(urlFragment);
        }
        break;

    case AUTH_VALIDATION_FAILED:
        /* Client had X minutes to validate account by email and didn't = too late */
        debug(LOG_INFO,"终端 %s(%s) 从网关服务器得到的令牌超时，删除终端并将其重定向到失败的验证消息。",client->ip, client->mac);
        client_list_delete(client);
        UNLOCK_CLIENT_LIST();
        
        safe_asprintf(&urlFragment, "%smessage=%s",
                      auth_server->authserv_msg_script_path_fragment, GATEWAY_MESSAGE_ACCOUNT_VALIDATION_FAILED);
        http_send_redirect_to_auth(r, urlFragment, "重定向到失败的验证消息");
        free(urlFragment);
        break;

    default:
        debug(LOG_WARNING,"终端 %s(%s) 从网关服务器得到未知的返回码(%d)，返回发送错误消息。",client->ip,client->mac,authresponse->authcode);
        client_list_delete(client); 
        UNLOCK_CLIENT_LIST();

        send_http_page_direct(r, "<html><body>内部错误，我们目前无法验证您的请求。</body></html>");
        break;
    }
}

static void
reply_auth_server_response(t_authresponse *authresponse, struct evhttps_request_context *context) {
    struct auth_response_client *authresponse_client = context->data;
    switch(authresponse_client->type)
    {
    case request_type_login:
        reply_login_response(authresponse, context);
        break;
    case request_type_logout:
        if (authresponse->authcode == AUTH_ERROR)
            debug(LOG_WARNING, "报告注销时的Auth服务器错误。");
        break;
    case request_type_counters:
        reply_counter_response(authresponse, context);
        break;
    }
}

void
process_auth_server_response(struct evhttp_request *req, void *ctx) { 
    if (ctx == NULL){
		debug (LOG_ERR, "不可能，回调函数传入的ctx为空。");
        return; // impossible here
	}

    t_authresponse authresponse;
	authresponse.authcode = AUTH_ERROR;

    debug(LOG_DEBUG, "fw_counter(回调函数) : 解析Auth服务器返回的数据。");
    if (parse_auth_server_response(&authresponse, req)) {
        debug(LOG_DEBUG, "fw_counter(回调函数) : 根据Auth服务器返回码，处理后续收尾工作。");
        reply_auth_server_response(&authresponse, ctx);
    } 
}
