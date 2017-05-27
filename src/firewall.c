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

/** @internal
  @file firewall.c
  @brief Firewall update functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  2006 Benoit Grégoire, Technologies Coeus inc. <bock@step.polymtl.ca>
  @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/uio.h>
#include <netdb.h>
#include <sys/time.h>

#include "httpd.h"
#include "safe.h"
#include "util.h"
#include "debug.h"
#include "conf.h"
#include "firewall.h"
#include "fw_iptables.h"
#include "auth.h"
#include "centralserver.h"
#include "client_list.h"
#include "commandline.h"
#include "wd_util.h"

static int _fw_deny_raw(const char *, const char *, const int);

/**
 * Allow a client access through the firewall by adding a rule in the firewall to MARK the user's packets with the proper
 * rule by providing his IP and MAC address
 * @param ip IP address to allow
 * @param mac MAC address to allow
 * @param fw_connection_state fw_connection_state Tag
 * @return Return code of the command
 */
int
fw_allow(t_client * client, int new_fw_connection_state)
{
    int result;
    int old_state = client->fw_connection_state;

    debug(LOG_DEBUG, "允许终端 %s(%s) 通行。状态：%d", client->ip, client->mac, new_fw_connection_state);
    client->fw_connection_state = new_fw_connection_state;

    /* Grant first */
    result = iptables_fw_access(FW_ACCESS_ALLOW, client->ip, client->mac, new_fw_connection_state);

    /* Deny after if needed. */
    if (old_state != FW_MARK_NONE) {
        debug(LOG_DEBUG, "清除终端 %s(%s) 以前的状态：%d", client->ip, client->mac, old_state);
        _fw_deny_raw(client->ip, client->mac, old_state);
    }

    return result;
}

/**
 * Allow a host through the firewall by adding a rule in the firewall
 * @param host IP address, domain or hostname to allow
 * @return Return code of the command
 */
int
fw_allow_host(const char *host)
{
    debug(LOG_DEBUG, "允许 %s 访问。", host);

    return iptables_fw_access_host(FW_ACCESS_ALLOW, host);
}

/**
 * @brief Deny a client access through the firewall by removing the rule in the firewall that was fw_connection_stateging the user's traffic
 * @param ip IP address to deny
 * @param mac MAC address to deny
 * @param fw_connection_state fw_connection_state Tag
 * @return Return code of the command
 */
int
fw_deny(t_client * client)
{
    int fw_connection_state = client->fw_connection_state;
    debug(LOG_DEBUG, "拒绝 %s(%s) 访问，网络状态：%d", client->ip, client->mac, client->fw_connection_state);

    client->fw_connection_state = FW_MARK_NONE; /* Clear */
    return _fw_deny_raw(client->ip, client->mac, fw_connection_state);
}

/** @internal
 * Actually does the clearing, so fw_allow can call it to clear previous mark.
 * @param ip IP address to deny
 * @param mac MAC address to deny
 * @param mark fw_connection_state Tag
 * @return Return code of the command
 */
static int
_fw_deny_raw(const char *ip, const char *mac, const int mark)
{
    return iptables_fw_access(FW_ACCESS_DENY, ip, mac, mark);
}

/** Passthrough for clients when auth server is down */
int
fw_set_authdown(void)
{
    debug(LOG_NOTICE, "Auth服务器......离线");

    return iptables_fw_auth_unreachable(FW_MARK_AUTH_IS_DOWN);
}

/** Remove passthrough for clients when auth server is up */
int
fw_set_authup(void)
{
    debug(LOG_NOTICE, "Auth服务器......在线");

    return iptables_fw_auth_reachable();
}

/* XXX DCY */
/**
 * Get an IP's MAC address from the ARP cache.
 * Go through all the entries in config->arp_table_path until we find the
 * requested IP address and return the MAC address bound to it.
 * @todo Make this function portable (using shell scripts?)
 */
char *
arp_get(const char *req_ip)
{
    FILE *proc         = NULL;
    char ip[16]     = {0};
    char mac[18]     = {0};
    char *reply;
    s_config *config = config_get_config();

    //通过IP来查Mac地址(/proc/net/arp)
    if (!(proc = fopen(config->arp_table_path, "r"))) {
        return NULL;
    }

    /* skip first line */
    while (!feof(proc) && fgetc(proc) != '\n') ;

    /* find ip, copy mac in reply */
    reply = NULL;
    while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[a-fa-f0-9:] %*s %*s", ip, mac) == 2)) {
        if (strcmp(ip, req_ip) == 0) {
            reply = safe_strdup(mac);
            break;
        }
    }

    fclose(proc);

    return reply;
}

char *
arp_get_ip(const char *req_mac)
{
    FILE *proc         = NULL;
    char ip[16]     = {0};
    char mac[18]     = {0};
    char *reply;
    s_config *config = config_get_config();

    //通过Mac来查IP地址(/proc/net/arp)
    if (!(proc = fopen(config->arp_table_path, "r"))) {
        return NULL;
    }

    /* skip first line */
    while (!feof(proc) && fgetc(proc) != '\n') ;

    /* find last mac, copy ip in reply */
    reply = NULL;
    while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[a-fa-f0-9:] %*s %*s", ip, mac) == 2)) {
        if (strcmp(mac, req_mac) == 0) {
            if(reply) {
                free(reply);
                reply = NULL;
            }
            reply = safe_strdup(ip);
        }
    }

    fclose(proc);

    return reply;
}

/** Initialize the firewall rules
 */
int
fw_init(void)
{
    debug(LOG_DEBUG, "fw_init()");
    int result = 0;
    int new_fw_state;
    t_client *client = NULL;

    debug(LOG_DEBUG, "fw_init() : init_icmp_socket");
    if (!init_icmp_socket()) {
        return 0;
    }

    debug(LOG_DEBUG, "fw_init() : iptables_fw_init");
    result = iptables_fw_init();

    if (restart_orig_pid) {
        debug(LOG_INFO, "恢复从父进程继承终端列表的防火墙规则。");
        LOCK_CLIENT_LIST();
        client = client_get_first_client();
        while (client) {
            new_fw_state = client->fw_connection_state;
            client->fw_connection_state = FW_MARK_NONE;
            fw_allow(client, new_fw_state);
            client = client->next;
        }
        UNLOCK_CLIENT_LIST();
    }

    debug(LOG_DEBUG, "fw_init() : end");
    return result;
}

/** Remove all auth server firewall whitelist rules
 */
void
fw_clear_authservers(void)
{
    debug(LOG_DEBUG, "Clearing the authservers list(清除Auth服务器防火墙规则)");
    iptables_fw_clear_authservers();
}

/** Add the necessary firewall rules to whitelist the authservers
 */
void
fw_set_authservers(void)
{
    debug(LOG_DEBUG, "Setting the authservers list(设置Auth服务器防火墙规则)");
    iptables_fw_set_authservers();
}

//>>>>> liudf added 20151224
void
fw_clear_pan_domains_trusted(void)
{
    debug(LOG_DEBUG, "Clear pan trust domains list");
    iptables_fw_clear_ipset_domains_trusted();
}

void
fw_set_pan_domains_trusted(void)
{
    debug(LOG_DEBUG, "Set pan trust domains list");
    iptables_fw_set_ipset_domains_trusted();
}

void
fw_refresh_inner_domains_trusted(void)
{
    debug(LOG_DEBUG, "Refresh inner trust domains list");
    iptables_fw_refresh_inner_domains_trusted();
}

void 
fw_clear_inner_domains_trusted(void)
{
    debug(LOG_DEBUG, "Clear inner trust domains list");
    iptables_fw_clear_inner_domains_trusted();
}

void 
fw_set_inner_domains_trusted(void)
{
    debug(LOG_DEBUG, "Setting inner trust domains list");
    iptables_fw_set_inner_domains_trusted();
}


void
fw_refresh_user_domains_trusted(void)
{
    debug(LOG_DEBUG, "Refresh user trust domains list");
    iptables_fw_refresh_user_domains_trusted();
}

void 
fw_clear_user_domains_trusted(void)
{
    debug(LOG_DEBUG, "Clear user trust domains list");
    iptables_fw_clear_user_domains_trusted();
}

void 
fw_set_user_domains_trusted(void)
{
    debug(LOG_DEBUG, "Setting user trust domains list");
    iptables_fw_set_user_domains_trusted();
}

void
fw_set_roam_mac(const char *mac)
{
    debug(LOG_DEBUG, "Set roam mac");
    iptables_fw_set_roam_mac(mac);
}

void
fw_clear_roam_maclist(void)
{
    debug(LOG_DEBUG, "Clear roam maclist");
    iptables_fw_clear_roam_maclist();
}

void
fw_set_trusted_maclist()
{
    debug(LOG_DEBUG, "设置Mac白名单的防火墙规则");
    iptables_fw_set_trusted_maclist();
}

void
fw_clear_trusted_maclist()
{
    debug(LOG_DEBUG, "清除Mac白名单的防火墙规则");
    iptables_fw_clear_trusted_maclist();
}

void
fw_set_untrusted_maclist()
{
    debug(LOG_DEBUG, "设置Mac黑名单的防火墙规则");
    iptables_fw_set_untrusted_maclist();
}

void
fw_clear_untrusted_maclist()
{
    debug(LOG_DEBUG, "清除Mac黑名单的防火墙规则");
    iptables_fw_clear_untrusted_maclist();
}

void
fw_set_mac_temporary(const char *mac, int which)
{
    debug(LOG_DEBUG, "Set trusted||untrusted mac [%s] temporary", mac);
    iptables_fw_set_mac_temporary(mac, which);
}

void
fw_set_trusted_mac(const char *mac)
{
    debug(LOG_DEBUG, "Clear untrusted maclist");
    iptables_fw_set_trusted_mac(mac);
}
//<<<<< liudf added end

/** Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog.
 * @return Return code of the fw.destroy script
 */
int
fw_destroy(void)
{
    debug(LOG_DEBUG, "fw_destroy()");
    
    debug(LOG_DEBUG, "fw_destroy() : close_icmp_socket");
    close_icmp_socket();
    
    debug(LOG_DEBUG, "fw_destroy() : iptables_fw_destroy");
    int re = iptables_fw_destroy();

    debug(LOG_DEBUG, "fw_destroy() : end");
    return re;
}

// liudf added 20160321
void
update_trusted_mac_status(t_trusted_mac *tmac)
{
    tmac->is_online = 0;

    if(tmac->ip == NULL) {
		//通过/proc/net/arp来查IP地址
        tmac->ip = arp_get_ip(tmac->mac);
    }

    if(tmac->ip != NULL) {
		//通过wdping命令来判断是否设备在线。
        tmac->is_online = is_device_online(tmac->ip);
    }
}

void
evhttps_update_trusted_mac_list_status(struct evhttps_request_context *context)
{
    debug(LOG_DEBUG, "evhttps_update_trusted_mac_list_status()");
    t_trusted_mac *p1 = NULL, *tmac_list = NULL;
    s_config *config = config_get_config();

    if(trusted_mac_list_dup(&tmac_list) == 0) {
        debug(LOG_DEBUG, "evhttps_update_trusted_mac_list_status() : Mac白名单列表为空。");
        debug(LOG_DEBUG, "evhttps_update_trusted_mac_list_status() : end");
        return;
    }
    
    struct auth_response_client authresponse_client;
    memset(&authresponse_client, 0, sizeof(struct auth_response_client));
    authresponse_client.type = request_type_counters;

    for(p1 = tmac_list; p1 != NULL; p1 = p1->next) {
        update_trusted_mac_status(p1);

        debug(LOG_DEBUG, "evhttps_update_trusted_mac_list_status() : %s %s %d", p1->ip, p1->mac, p1->is_online);
        if (config->auth_servers != NULL && p1->is_online) {
			debug(LOG_DEBUG, "fw_counter() : 获得请求Auth服务器的地址。");
            char *uri = get_auth_uri(REQUEST_TYPE_COUNTERS, trusted_client, p1);
            if (uri) {
                authresponse_client.client = p1;//增加逻辑 By LiuQiQuan

			    debug(LOG_DEBUG, "fw_counter() : 请求Auth服务器(%s)。",REQUEST_TYPE_COUNTERS);
                evhttps_request(context, uri, 2, process_auth_server_response, &authresponse_client);
                free(uri);
            }
        }
            
    }
    
    clear_dup_trusted_mac_list(tmac_list);
    debug(LOG_DEBUG, "evhttps_update_trusted_mac_list_status() : end");
}

void
update_trusted_mac_list_status(void)
{
    debug(LOG_DEBUG, "update_trusted_mac_list_status()");

    t_authresponse authresponse;
    t_trusted_mac *p1 = NULL, *tmac_list = NULL;
    s_config *config = config_get_config();

    if(trusted_mac_list_dup(&tmac_list) == 0) {
        debug(LOG_DEBUG, "update_trusted_mac_list_status() : Mac白名单列表为空。");
        debug(LOG_DEBUG, "update_trusted_mac_list_status() : end");
        return;
    }
    
    int flag = 0;
    for(p1 = tmac_list; p1 != NULL; p1 = p1->next) {
        update_trusted_mac_status(p1);
        debug(LOG_DEBUG, "update_trusted_mac_list_status() : 更新白名单终端的信息：%s(%s) ... %s", p1->ip, p1->mac, (p1->is_online?"在线":"离线"));
        if (config->auth_servers != NULL && p1->is_online) {
            debug(LOG_DEBUG, "update_trusted_mac_list_status() : 给在线终端(%s)上报流量(/wifidog/auth?counters)",p1->ip);
            auth_server_request(&authresponse, REQUEST_TYPE_COUNTERS, p1->ip, p1->mac, "null", 0,
                                0, 0, 0, 0, 0, "null", 0/*is_device_wired(p1->mac)*/);
            flag = 1;
        }            
    }
    
    if (flag) {
        debug(LOG_DEBUG, "update_trusted_mac_list_status() : 关闭Auth服务器连接。");
        close_auth_server();
	}
    
    clear_dup_trusted_mac_list(tmac_list);
    debug(LOG_DEBUG, "update_trusted_mac_list_status() : end");
}

static void
fw_client_operation(int operation, t_client *p1)
{
    switch(operation) {
    case 1:
  	    debug(LOG_DEBUG, "终端(%s)网络阻止，增加防火墙规则。",p1->ip);
	    fw_deny(p1);
        break;
    case 2:
  	    debug(LOG_DEBUG, "终端(%s)网络通行，增加防火墙规则。",p1->ip);
	    fw_allow(p1, FW_MARK_KNOWN);
        break;
    }
}

void
fw_client_process_from_authserver_response(t_authresponse *authresponse, t_client *p1)
{
    int operation = 0; // 0: no operation; 1: deny; 2: allow;
    t_client *tmp_c;
    s_config *config = config_get_config();

    LOCK_CLIENT_LIST();
    tmp_c = client_list_find_by_client(p1);
    if (NULL == tmp_c) {
        UNLOCK_CLIENT_LIST();
        debug(LOG_NOTICE, "终端(%s)已被删除。 跳过验证返回码处理。",p1->ip);
        return;       /* Next client please */
    }

    if (config->auth_servers != NULL && tmp_c->is_online) {
        switch (authresponse->authcode) {
        case AUTH_DENIED:
            debug(LOG_NOTICE, "终端(%s)返回码<0>被拒绝, 删除终端和防火墙规则。", tmp_c->ip);
            client_list_delete(tmp_c);
            operation = 1;
            break;

        case AUTH_VALIDATION_FAILED:
            debug(LOG_NOTICE, "终端(%s)返回码<6>验证超时, 删除终端和防火墙规则。",tmp_c->ip);
            client_list_delete(tmp_c);
            operation = 1;
            break;

        case AUTH_ALLOWED:
            if (tmp_c->fw_connection_state != FW_MARK_KNOWN) {
                debug(LOG_INFO, "终端(%s)返回码<1>访问已更改为允许, 刷新防火墙和清除计数器。",tmp_c->ip);
                if (tmp_c->fw_connection_state != FW_MARK_PROBATION) {
                    tmp_c->counters.incoming_delta =
                     tmp_c->counters.outgoing_delta =
                     tmp_c->counters.incoming =
                     tmp_c->counters.outgoing = 0;
                } else {
                    debug(LOG_INFO,"终端(%s)正在验证，跳过清除计数器。",tmp_c->ip);
                }                
                operation = 2;
            }
            break;
        case AUTH_VALIDATION:
            debug(LOG_INFO, "终端(%s)返回码<5>用户在验证期间，不执行任何操作。", tmp_c->ip);
            break;
        case AUTH_ERROR:
            debug(LOG_WARNING, "终端(%s)返回码<-1>与验证服务器通信时出错。", tmp_c->ip);
            break;
        default:
            debug(LOG_ERR, "终端(%s)返回码<%d>未知的验证码。", tmp_c->ip,authresponse->authcode);
            break;
        }
    }
    UNLOCK_CLIENT_LIST();

    fw_client_operation(operation, p1);
}

void
evhttps_fw_sync_with_authserver(struct evhttps_request_context *context)
{
    t_client *p1, *p2, *worklist;
    s_config *config = config_get_config();

    debug(LOG_DEBUG, "fw_counter() : 从防火墙获取流量");
    if (-1 == iptables_fw_counters_update()) {
        debug(LOG_ERR, "fw_counter() : 无法从防火墙获取流量!");
		return;
    }

    LOCK_CLIENT_LIST();

    /* XXX Ideally, from a thread safety PoV, this function should build a list of client pointers,
     * iterate over the list and have an explicit "client still valid" check while list is locked.
     * That way clients can disappear during the cycle with no risk of trashing the heap or getting
     * a SIGSEGV.
     */
    g_online_clients = client_list_dup(&worklist);
    UNLOCK_CLIENT_LIST();
    debug(LOG_DEBUG, "fw_counter() : 获得在线的终端数：%d",g_online_clients);

    struct auth_response_client authresponse_client;
    memset(&authresponse_client, 0, sizeof(struct auth_response_client));
    authresponse_client.type = request_type_counters;

    for (p1 = p2 = worklist; NULL != p1; p1 = p2) {
        p2 = p1->next;      

        debug(LOG_DEBUG, "fw_counter() : 处理在线终端(%s)",p1->ip);

        /* Ping客户端，如果他回应，它会保持链接上的活动。
         * 但是，如果防火墙阻止它，它将无济于事。
         * 建议他的处理方式是保持DHCP租期的时间非常多
         * short:  Shorter than config->checkinterval * config->clienttimeout */
        icmp_ping(p1->ip);

        /* 只有在拥有auth服务器的情况下才能更新远程服务器上的计数器*/
        if (config->auth_servers != NULL && p1->is_online) {
            debug(LOG_DEBUG, "fw_counter() : 给在线终端(%s)上报流量(/wifidog/auth?counters)",p1->ip);

			debug(LOG_DEBUG, "fw_counter() : 获得请求Auth服务器的地址。");
            char *uri = get_auth_uri(REQUEST_TYPE_COUNTERS, online_client, p1);
            if (uri) {
                authresponse_client.client = p1;

			    debug(LOG_DEBUG, "fw_counter() : 请求Auth服务器(%s)。",REQUEST_TYPE_COUNTERS);
                evhttps_request(context, uri, 2, process_auth_server_response, &authresponse_client);
                free(uri);
            }
        }         
    }
    
    client_list_destroy(worklist);
}

/**Probably a misnomer, this function actually refreshes the entire client list's traffic counter, re-authenticates every client with the central server and update's the central servers traffic counters and notifies it if a client has logged-out.
 * @todo Make this function smaller and use sub-fonctions
 */
void
fw_sync_with_authserver(void)
{
	debug(LOG_DEBUG, "get_counters()");
    t_authresponse authresponse;
    t_client *p1, *p2, *worklist, *tmp;
    s_config *config = config_get_config();
	char date_str[50];

    debug(LOG_DEBUG, "get_counters() : 从防火墙获取流量");
    if (-1 == iptables_fw_counters_update()) {
        debug(LOG_ERR, "无法从防火墙获取流量!");
        return;
    }
       
    LOCK_CLIENT_LIST();

    /* XXX Ideally, from a thread safety PoV, this function should build a list of client pointers,
     * iterate over the list and have an explicit "client still valid" check while list is locked.
     * That way clients can disappear during the cycle with no risk of trashing the heap or getting
     * a SIGSEGV.
     */
    g_online_clients = client_list_dup(&worklist);
    UNLOCK_CLIENT_LIST();
    debug(LOG_DEBUG, "get_counters() : 获得在线的终端数：%d",g_online_clients);

    int flag = 0;
    for (p1 = p2 = worklist; NULL != p1; p1 = p2) {
        p2 = p1->next;

        debug(LOG_DEBUG, "get_counters() : 处理在线终端(%s)",p1->ip);
        /* Ping客户端，如果他回应，它会保持链接上的活动。
         * 但是，如果防火墙阻止它，它将无济于事。
         * 建议他的处理方式是保持DHCP租期的时间非常多
         * short:  Shorter than config->checkinterval * config->clienttimeout */
        icmp_ping(p1->ip);

        /* 只有在拥有auth服务器的情况下才能更新远程服务器上的计数器*/
        if (config->auth_servers != NULL && p1->is_online) 
        {
            debug(LOG_DEBUG, "get_counters() : 给在线终端(%s)上报流量(/wifidog/auth?counters)",p1->ip);
            auth_server_request(&authresponse, REQUEST_TYPE_COUNTERS, p1->ip, p1->mac, p1->token, p1->counters.incoming,
                                p1->counters.outgoing, p1->counters.incoming_delta, p1->counters.outgoing_delta,
                                // liudf added 20160112
                                p1->first_login, (p1->counters.last_updated - p1->first_login), 
                                p1->name?p1->name:"null", p1->wired);
            flag = 1;
        }

        time_t current_time = time(NULL);
        if (p1->counters.last_updated + (config->checkinterval * config->clienttimeout) <= current_time) {
            /* Timing out user */
			gettimestr(p1->counters.last_updated,date_str,sizeof(date_str)-1);
            debug(LOG_DEBUG, "get_counters() : 终端(%s)超时%ld/%ld秒(最后更新:%s)，删除超时的终端并在防火墙中拒绝终端。",
                  p1->ip, current_time - p1->counters.last_updated,config->checkinterval * config->clienttimeout,date_str);
            
            LOCK_CLIENT_LIST();
            tmp = client_list_find_by_client(p1);
            if (NULL != tmp) {
                debug(LOG_DEBUG, "get_counters() : 注销终端(%s)",p1->ip);
                logout_client(tmp);
            } else {
                debug(LOG_DEBUG, "get_counters() : 终端(%s)已被删除，不需要注销登陆",p1->ip);
            }
            UNLOCK_CLIENT_LIST();
        } else if (config->auth_servers != NULL && p1->is_online) {
            //增加逻辑 By LiuQiQuan    
            //上面两行增加判断，省得进去判断了。

            /*
             * This handles any change in the status this allows us
             * to change the status of a user while he's connected
             *
             * Only run if we have an auth server configured!
             */
            debug(LOG_DEBUG, "get_counters() : 在线终端(%s)验证Auth服务器返回值(%d)",p1->ip,authresponse.authcode);
            fw_client_process_from_authserver_response(&authresponse, p1);
        }
    }
    
    if (flag) {
        debug(LOG_DEBUG, "get_counters() : 关闭Auth服务器连接。");
        close_auth_server();
    }

    client_list_destroy(worklist);    

    debug(LOG_DEBUG, "get_counters() : end");
}
