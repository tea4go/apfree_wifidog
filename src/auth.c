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
/** @file auth.c
    @brief Authentication handling thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
    @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>

#include "httpd.h"
#include "http.h"
#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "util.h"
#include "wd_util.h"

/** 启动一个线程，定期检查是否有任何连接超时
@param arg Must contain a pointer to a string containing the IP adress of the client to check to check
@todo Also pass MAC adress? 
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void
thread_client_timeout_check(const void *arg)
{
    debug(LOG_DEBUG, "fw_counter()");
    debug(LOG_DEBUG, "fw_counter() : 每隔 %d 秒发送一次(/wifidog/auth/?stage=counters)请求给Auth服务器。",config_get_config()->checkinterval+3);

    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;
    t_auth_serv *auth_server = get_auth_server();
    struct evhttps_request_context *context = NULL;

    while (1) {
	    //增加逻辑 By LiuQiQuan
		auth_server = get_auth_server();
		if (auth_server==NULL)
		{
		    debug(LOG_ERR, "没有可用的Auth服务器，进程将退出。");
			exit(0);
		}

		if (auth_server->authserv_use_ssl && context==NULL) {
			debug(LOG_DEBUG, "执行HTTPs网络初始化。");
			context = evhttps_context_init();
			if (!context) {
				debug(LOG_ERR, "调用HTTPs初始化函数失败，进程将立刻退出。");
				exit(0);
			}
		}

        /* Sleep for config.checkinterval seconds... */
        timeout.tv_sec = time(NULL) + config_get_config()->checkinterval+3;//增加逻辑 By LiuQiQuan 推后3秒这样日志好看。
        timeout.tv_nsec = 0;

        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);

        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);

        if (auth_server->authserv_use_ssl) {
            debug(LOG_DEBUG, "fw_counter() : 所有的终端都上报流量给Auth服务器(HTTPs)。");
            evhttps_fw_sync_with_authserver(context);

            debug(LOG_DEBUG, "fw_counter() : 对于Mac白名单也需要上报流量给Auth服务器(HTTPs)。");
            evhttps_update_trusted_mac_list_status(context);
        } else {
            debug(LOG_DEBUG, "fw_counter() : 所有的终端都上报流量给Auth服务器。");
            fw_sync_with_authserver(); 

            debug(LOG_DEBUG, "fw_counter() : 对于Mac白名单也需要上报流量给Auth服务器。");
            update_trusted_mac_list_status();
        }  
    }

    if (auth_server->authserv_use_ssl) {
        evhttps_context_exit(context);
    }
    debug(LOG_DEBUG, "fw_counter() : end");
}

void
evhttps_logout_client(void *ctx, t_client *client)
{
    struct evhttps_request_context *context = (struct evhttps_request_context *)ctx;
    const s_config *config = config_get_config();

    fw_deny(client);
    client_list_remove(client);

    if (config->auth_servers != NULL) {
        debug(LOG_DEBUG, "http_callback_auth() : 获得请求Auth服务器的地址。");
        char *uri = get_auth_uri(REQUEST_TYPE_LOGOUT, online_client, client);
        if (uri) {
            struct auth_response_client authresponse_client;
            memset(&authresponse_client, 0, sizeof(authresponse_client));
            authresponse_client.type = request_type_logout;

			debug(LOG_DEBUG, "http_callback_auth() : 请求Auth服务器(%s)。",REQUEST_TYPE_LOGOUT);
            evhttps_request(context, uri, 2, process_auth_server_response, &authresponse_client);
            free(uri);
        }
    }
}

/**
 * @brief Logout a client and report to auth server.
 *
 * This function assumes it is being called with the client lock held! This
 * function remove the client from the client list and free its memory, so
 * client is no langer valid when this method returns.
 *
 * @param client Points to the client to be logged out
 */
void
logout_client(t_client * client)
{
    debug(LOG_DEBUG, "logout_client()");
    t_authresponse authresponse;
    const s_config *config = config_get_config();

    debug(LOG_DEBUG, "logout_client() : 增加防火墙规则阻止终端网络通行。");
    fw_deny(client);
    debug(LOG_DEBUG, "logout_client() : 从在线列表删除终端信息。");
    client_list_remove(client);

    /* Advertise the logout if we have an auth server */
    if (config->auth_servers != NULL) {
        debug(LOG_DEBUG, "logout_client() : 注销终端需要到Auth服务器鉴权");
		UNLOCK_CLIENT_LIST();
        auth_server_request(&authresponse, REQUEST_TYPE_LOGOUT,
                            client->ip, client->mac, client->token,
                            client->counters.incoming, client->counters.outgoing, 
                            client->counters.incoming_delta, client->counters.outgoing_delta,
                            //>>> liudf added 20160112
                            client->first_login, (client->counters.last_updated - client->first_login),
                            client->name?client->name:"null", client->wired);
        close_auth_server();
        if (authresponse.authcode == AUTH_ERROR)
            debug(LOG_WARNING, "logout_client() : 注销终端时Auth服务器返回错误)");
        LOCK_CLIENT_LIST();
    }

    client_free_node(client);
    debug(LOG_DEBUG, "logout_client() : end");
}

/** Authenticates a single client against the central server and returns when done
 * Alters the firewall rules depending on what the auth server says
@param r httpd request struct
*/
void
authenticate_client(request * r)
{
    t_client *client, *tmp;
    t_authresponse auth_response; 
    char *urlFragment = NULL;

    LOCK_CLIENT_LIST();
    client = client_dup(client_list_find_by_ip(r->clientAddr));
    UNLOCK_CLIENT_LIST();

    if (client == NULL) {
        debug(LOG_ERR, "http_callback_auth() : 终端(%s)已被删除。 跳过验证返回码处理。", r->clientAddr);
        send_http_page(r, "错误", "终端已被删除。 跳过验证返回码处理。");
        return;
    }

    s_config    *config = config_get_config();
    t_auth_serv *auth_server = get_auth_server();

    //LiuQiQuan 这段未完成。
    if (auth_server->authserv_use_ssl) {
        debug(LOG_DEBUG, "http_callback_auth() : 初始化HTTPs会话。");
        struct evhttps_request_context *context = evhttps_context_init();
        if (!context) {
            debug(LOG_ERR, "初始化HTTPs会话失败，将删除终端。");
            client_list_destroy(client);
            return;
        }

        debug(LOG_DEBUG, "http_callback_auth() : 获得请求Auth服务器的地址。");
        char *uri = get_auth_uri(REQUEST_TYPE_LOGIN, online_client, client);
        if (uri) {
            struct auth_response_client authresponse_client;
            memset(&authresponse_client, 0, sizeof(authresponse_client));
            authresponse_client.type    = request_type_login;
            authresponse_client.client  = client;
            authresponse_client.req     = r;
            
			debug(LOG_DEBUG, "http_callback_auth() : 请求Auth服务器(%s)。",REQUEST_TYPE_LOGIN);
            evhttps_request(context, uri, 2, process_auth_server_response, &authresponse_client);
            free(uri);
        }

        evhttps_context_exit(context);
        return;
    }

    char *token = NULL;
    httpVar *var = NULL;
    /* Users could try to log in(so there is a valid token in
     * request) even after they have logged in, try to deal with
     * this */
    if ((var = httpdGetVariableByName(r, "token")) != NULL) {
        token = safe_strdup(var->value);
    } else {
        token = safe_strdup(client->token);
    }

    //<<<
    /* 
     * At this point we've released the lock while we do an HTTP request since it could
     * take multiple seconds to do and the gateway would effectively be frozen if we
     * kept the lock.
     */
	debug(LOG_DEBUG, "http_callback_auth() : 调用Auth服务器网络请求(/wifidog/auth/?stage=login)");
    auth_server_request(&auth_response, REQUEST_TYPE_LOGIN, client->ip, client->mac, token, 0, 0, 0, 0, 0, 0, "null", client->wired);

	debug(LOG_DEBUG, "http_callback_auth() : 关闭Auth服务器网络连接");
    close_auth_server(); 
    
    /* Prepare some variables we'll need below */
    
    
    LOCK_CLIENT_LIST();
    /* can't trust the client to still exist after n seconds have passed */
    tmp = client_list_find_by_client(client);
    if (NULL == tmp) {
        debug(LOG_ERR, "http_callback_auth() : 不能找到终端 %s(%s)", client->ip, client->mac);
        UNLOCK_CLIENT_LIST();
        client_list_destroy(client);    /* Free the cloned client */
        free(token);
        send_http_page(r, "错误", "不能找到终端。");
        return;
    }

    client_list_destroy(client);        /* Free the cloned client */
    client = tmp;
    if (strcmp(token, client->token) != 0) {
        /* If token changed, save it. */
        debug(LOG_DEBUG, "http_callback_auth() : 终端的令牌变化需要更新。");
        free(client->token);
        client->token = token;
    } else {
        free(token);
    }
    debug(LOG_DEBUG, "http_callback_auth() : 终端  %s(%s) 的令牌：%s",client->ip, client->mac,client->token);  
    
    switch (auth_response.authcode) {

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
        //gw_message?message=xxxx
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
        {
            LOCK_OFFLINE_CLIENT_LIST();
            t_offline_client *o_client = offline_client_list_find_by_mac(client->mac);
            if(o_client)
                offline_client_list_delete(o_client);
            UNLOCK_OFFLINE_CLIENT_LIST();
        }
        
        //<<< liudf added end
        served_this_session++;
        if(httpdGetVariableByName(r, "type")) {
            send_http_page_direct(r, "<html><body>微信授权成功！</body><html>");
        } else {
			char time_str[64];
            safe_asprintf(&urlFragment, "%sgw_id=%s&channel_path=%s&mac=%s&name=%s&call_counter=%s", 
                auth_server->authserv_portal_script_path_fragment, 
                config->gw_id,
                g_channel_path?g_channel_path:"null",
                client->mac?client->mac:"null",
                client->name?client->name:"null",
				gettimeofdaystr(time_str,sizeof(time_str)));
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
        debug(LOG_WARNING,"终端 %s(%s) 从网关服务器得到的未知的返回码(%d)，返回发送错误消息。",client->ip, client->mac,auth_response.authcode);
        client_list_delete(client);    
        UNLOCK_CLIENT_LIST();
        
        send_http_page_direct(r, "<htm><body>内部错误，我们目前无法验证您的请求。</body></html>");
        break;
    }

    return;
}
