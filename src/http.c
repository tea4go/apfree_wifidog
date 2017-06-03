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
/** @file http.c
  @brief HTTP IO functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Grégoire
  @author Copyright (C) 2007 David Bird <david@coova.com>
  @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>

 */
/* Note that libcs other than GLIBC also use this macro to enable vasprintf */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <zlib.h>

#include <httpd.h>

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "auth.h"
#include "firewall.h"
#include "http.h"
#include "client_list.h"
#include "common.h"
#include "centralserver.h"
#include "util.h"
#include "wd_util.h"
#include "gateway.h"
#include "https_server.h"
#include "simple_http.h"
#include "wdctl_thread.h"
#include "version.h"

#define APPLE_REDIRECT_MSG  "<!DOCTYPE html>"	\
				"<html>"						\
				"<title>Success</title>"		\
				"<script type=\"text/javascript\">"	\
					"window.location.replace(\"%s\");"	\
				"</script>"	\
				"<body>"	\
				"Success"	\
				"</body>"	\
				"</html>"


const char *apple_domains[] = {
					"captive.apple.com",
					"www.apple.com",
					NULL
};

const char *apple_wisper = "<!DOCTYPE html>"
				"<html>"
				"<script type=\"text/javascript\">"
					"window.setTimeout(function() {location.href = \"captive.apple.com/hotspot-detect.html\";}, 12000);"
				"</script>"
				"<body>"
				"</body>"
				"</html>";

static int
_is_apple_captive(const char *domain)
{
	int i = 0;
	while(apple_domains[i] != NULL) {
		if(strcmp(domain, apple_domains[i]) == 0)
			return 1;
		i++;
	}

	return 0;
}

static int
_special_process(request *r, const char *mac, const char *redir_url)
{
	t_offline_client *o_client = NULL;

	if(_is_apple_captive(r->request.host)) {
		int interval = 0;
		LOCK_OFFLINE_CLIENT_LIST();
    	o_client = offline_client_list_find_by_mac(mac);
    	if(o_client == NULL) {
    		o_client = offline_client_list_add(r->clientAddr, mac);
    	} else {
			o_client->last_login = time(NULL);
			interval = o_client->last_login - o_client->first_login;
		}

		debug(LOG_DEBUG, "Into captive.apple.com hit_counts %d interval %d http version %d",
				o_client->hit_counts, interval, r->request.version);

		o_client->hit_counts++;

		if(o_client->client_type == 1 ) {
    		UNLOCK_OFFLINE_CLIENT_LIST();
			if(interval > 20 && r->request.version == HTTP_1_0) {
				fw_set_mac_temporary(mac, 0);
				http_send_apple_redirect(r, redir_url);
			} else if(o_client->hit_counts > 2 && r->request.version == HTTP_1_0)
				http_send_apple_redirect(r, redir_url);
			else {
				http_send_redirect(r, redir_url, "重定向到登录页面");
			}
		} else {
			o_client->client_type = 1;
			UNLOCK_OFFLINE_CLIENT_LIST();
			http_relay_wisper(r);
		}
		return 1;
	}

	return 0;
}
//<<< liudf added end

/** The 404 handler is also responsible for redirecting to the auth server */
void
http_callback_404(httpd * webserver, request * r, int error_code)
{
	char tmp_url[MAX_BUF] = {0};
	snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
         r->request.host, r->request.path, r->request.query[0] ? "?" : "", r->request.query);
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
		return;
	}

	if (!is_online()) {
        debug(LOG_DEBUG, "http_callback_404() : 网关服务器不在线，返回不在线页面。捕获 %s 请求 [%s]", r?r->clientAddr:"空",tmp_url);
		char *msg = evb_2_string(evb_internet_offline_page, NULL);
        send_http_page_direct(r, msg);
		free(msg);
    } else if (!is_auth_online()) {
        debug(LOG_DEBUG, "http_callback_404() : Auth服务器不在线，返回不在线页面。捕获 %s 请求 [%s]", r?r->clientAddr:"空",tmp_url);
		char *msg = evb_2_string(evb_authserver_offline_page, NULL);
        send_http_page_direct(r, msg);
		free(msg);
    } else {
		/* Re-direct them to auth server */
		const s_config *config = config_get_config();
        char  mac[18] = {0};
        int nret = br_arp_get_mac(r->clientAddr, mac);  
		if (nret == 0) {
            strncpy(mac, "ff:ff:ff:ff:ff:ff", 17);
        }
  	    
    	char *url = httpdUrlEncode(tmp_url);	
		char *redir_url = evhttpd_get_full_redir_url(mac, r->clientAddr, url);
  	    debug (LOG_INFO, "捕获 %s 请求 [%s]==>[%s]", r->clientAddr, tmp_url,redir_url);

		if (nret) {  // if get mac success              
			t_client *clt = NULL;
            //debug(LOG_DEBUG, "http_callback_404() : 通过IP获得Mac地址：%s(%s)", r->clientAddr, mac);

			//>>> liudf 20160106 added
			if(_special_process(r, mac, redir_url)) {
                debug(LOG_DEBUG, "http_callback_404() : 执行物理处理(special_process)");
            	goto end_process;
			}

			// if device has login; but after long time reconnected router, its ip changed
			LOCK_CLIENT_LIST();
			clt = client_list_find_by_mac(mac);
			if(clt && strcmp(clt->ip, r->clientAddr) != 0) {
				fw_deny(clt);
				free(clt->ip);
				clt->ip = safe_strdup(r->clientAddr);
				fw_allow(clt, FW_MARK_KNOWN);
				UNLOCK_CLIENT_LIST();
                debug(LOG_DEBUG, "http_callback_404() : 终端已经登录，用新的IP替换它。");
				http_send_redirect(r, tmp_url, "终端已经登录。");
            	goto end_process;
			}
			UNLOCK_CLIENT_LIST();

            if (config->wired_passed && br_is_device_wired(mac)) {
                debug(LOG_DEBUG, "http_callback_404() : 有线终端(%s)增加到白名单。", mac);
                if (!is_trusted_mac(mac))
                    add_trusted_maclist(mac);
                http_send_redirect(r, tmp_url, "终端是有线接入。");
                goto end_process;
            }
        }

		if(config->js_filter)
			//通过定时器自动转向登录网页。
			http_send_js_redirect(r, redir_url);
		else
			//通过手动点击转向登录网页。
			http_send_redirect(r, redir_url, "重定向到登录页面");

end_process:
		if (redir_url) free(redir_url);
		if (url) free(url);
    }

//	debug(LOG_DEBUG, "http_callback_404() : end");
}

void
http_callback_wifidog(httpd * webserver, request * r)
{
    send_http_page(r, "WiFiDog", "请使用菜单浏览此WiFiDog安装的功能。");
}

void
http_callback_about(httpd * webserver, request * r)
{
    send_http_page(r, "About WiFiDog", "This is WiFiDog version <strong>" VERSION "</strong>");
}

void
http_callback_status(httpd * webserver, request * r)
{
    const s_config *config = config_get_config();
    char *status = NULL;
    char *buf;

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "请求状态页，强制认证。");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    status = get_status_text();
    safe_asprintf(&buf, "<pre>%s</pre>", status);
    send_http_page(r, "WiFi防火墙状态", buf);
    free(buf);
    free(status);
}

/** @brief Convenience function to redirect the web browser to the auth server
 * @param r The request
 * @param urlFragment The end of the auth server URL to redirect to (the part after path)
 * @param text The text to include in the redirect header ant the mnual redirect title */
void
http_send_redirect_to_auth(request * r, const char *urlFragment, const char *text)
{
    char *protocol = NULL;
    int port = 80;
    t_auth_serv *auth_server = get_auth_server();

    if (auth_server->authserv_use_ssl) {
        protocol = "https";
        port = auth_server->authserv_ssl_port;
    } else {
        protocol = "http";
        port = auth_server->authserv_http_port;
    }

    char *url = NULL;
    safe_asprintf(&url, "%s://%s:%d%s%s",
                  protocol, auth_server->authserv_hostname, port, auth_server->authserv_path, urlFragment);
    http_send_redirect(r, url, text);
    free(url);
}

/** @brief Sends a redirect to the web browser
 * @param r The request
 * @param redir_url The redir_url to redirect to
 * @param text The text to include in the redirect header and the manual redirect link title.  NULL is acceptable 
 * 通过手动点击转向登录网页。
 */
void
http_send_redirect(request * r, const char *redir_url, const char *text)
{
    char *message = NULL;
    char *header = NULL;
    char *response = NULL;
    /* Re-direct them to auth server */
    debug(LOG_DEBUG, "将终端浏览器(手动)重定向到Auth服务器：%s", redir_url);
    safe_asprintf(&header, "Location: %s", redir_url);
	// liudf 20160104; change 302 to 307
    safe_asprintf(&response, "307 %s\r\n", text ? text : "重定向");
    httpdSetResponse(r, response);
    httpdAddHeader(r, header);
    free(response);
    free(header);

    safe_asprintf(&message, "<html><body>请<a href='%s'>点击这里</a>。</body></html>", redir_url);
    httpdOutputDirect(r, message);
	_httpd_closeSocket(r);
    free(message);
}

void
http_callback_auth(httpd * webserver, request * r)
{
	char tmp_url[MAX_BUF] = {0};
	snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
             r->request.host, r->request.path, r->request.query[0] ? "?" : "", r->request.query);
    
	debug(LOG_INFO, "终端 %s 访问网关服务器。地址：%s", r->clientAddr,tmp_url);
    t_client *client;
    httpVar *token;
    char *mac;
    httpVar *logout;

    logout = httpdGetVariableByName(r, "logout");
    token = httpdGetVariableByName(r, "token");

    if (token) {
        /* They supplied variable "token" */
        if (!(mac = arp_get(r->clientAddr))) {
            /* We could not get their MAC address */
            debug(LOG_ERR, "找不到(%s)对应的Mac地址。", r->clientAddr);
            send_http_page(r, "错误", "找不到对应的Mac地址。");
        } else {
            /* We have their MAC address */
            LOCK_CLIENT_LIST();
			client = client_list_find(r->clientAddr, mac);

            if (logout != NULL) {
                if (client != NULL) {
  				    debug(LOG_NOTICE, "http_callback_auth() : 注销终端 %s(%s)", r->clientAddr,mac);
					logout_client(client);
				} else {
					debug(LOG_INFO, "终端 %s(%s) 已经注销过", r->clientAddr,mac);
				}				
                UNLOCK_CLIENT_LIST();

				send_http_page(r, "提示", "终端注销成功。");
			}else {
				if (client == NULL) {
					debug(LOG_NOTICE, "新建终端 %s(%s)", r->clientAddr,mac);
					client_list_add(r->clientAddr, mac, token->value);
				} else {
					debug(LOG_DEBUG, "http_callback_auth() : 终端 %s(%s) 已经在终端列表中", r->clientAddr,mac);
				}
                UNLOCK_CLIENT_LIST();

 			    debug(LOG_DEBUG, "http_callback_auth() : 终端 %s(%s) 请求Auth服务器验证返回码(/wifidog/auth)。", r->clientAddr,mac);
				authenticate_client(r);
			}

            free(mac);
        }
    } else {
        /* They did not supply variable "token" */
        send_http_page(r, "错误", "没有找到token字段。");
    }
	debug(LOG_DEBUG, "http_callback_auth() : end");
}

//增加逻辑 LiuQiQuan (主动注销登录未完成)
void
http_callback_disconnect(httpd * webserver, request * r)
{
	debug(LOG_DEBUG, "http_callback_disconnect()");
    const s_config *config = config_get_config();
    /* XXX How do you change the status code for the response?? */
    httpVar *token = httpdGetVariableByName(r, "token");
    httpVar *mac = httpdGetVariableByName(r, "mac");

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "http_callback_disconnect() : Disconnect requested, forcing authentication(断开请求，强制认证)");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    if (token && mac) {
        t_client *client;

        LOCK_CLIENT_LIST();
        client = client_list_find_by_mac(mac->value);

        if (!client || strcmp(client->token, token->value)) {
            UNLOCK_CLIENT_LIST();
			if (client) 
               debug(LOG_INFO, "http_callback_disconnect() : 断开 %s 连接失败，传入的token不正确。令牌：%s",mac->value,token->value);
			else
               debug(LOG_INFO, "http_callback_disconnect() : 断开 %s 连接失败，没找到mac地址对应的终端。",mac->value);
            httpdOutput(r, "无效的Mac地址或Token。");
			debug(LOG_DEBUG, "http_callback_disconnect() : end");
            return;
        }

        /* TODO: get current firewall counters */
        logout_client(client);
        UNLOCK_CLIENT_LIST();

    } else {
        debug(LOG_INFO, "断开连接需要传入mac和token字段。");
        httpdOutput(r, "断开连接需要传入mac和token字段。");
        return;
    }
	debug(LOG_DEBUG, "http_callback_disconnect() : end");
    return;
}

// liudf added 20160421
void
http_callback_temporary_pass(httpd * webserver, request * r)
{
    const s_config *config = config_get_config();
    httpVar *mac = httpdGetVariableByName(r, "mac");

	if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Disconnect requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

	if(mac) {
        debug(LOG_INFO, "Temporary passed %s", mac->value);
		fw_set_mac_temporary(mac->value, 0);
        httpdOutput(r, "startWeChatAuth();");
	} else {
        debug(LOG_INFO, "Temporary pass called without  MAC given");
        httpdOutput(r, "MAC need to be specified");
        return;
    }

	return;
}

void
send_http_page(request * r, const char *title, const char *message)
{
    s_config *config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;

    fd = open(config->htmlmsgfile, O_RDONLY);
    if (fd == -1) {
        debug(LOG_CRIT, "打开文件(%s)失败。原因：%s", config->htmlmsgfile, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info) == -1) {
        debug(LOG_CRIT, "读取文件状态(%s)失败。原因：%s", config->htmlmsgfile, strerror(errno));
        close(fd);
        return;
    }
    // Cast from long to unsigned int
    buffer = (char *)safe_malloc((size_t) stat_info.st_size + 1);
    written = read(fd, buffer, (size_t) stat_info.st_size);
    if (written == -1) {
        debug(LOG_CRIT, "读取文件内容(%s)失败。原因：%s", config->htmlmsgfile, strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);

    buffer[written] = 0;
    httpdAddVariable(r, "title", title);
    httpdAddVariable(r, "message", message);
    httpdAddVariable(r, "nodeID", config->gw_id);

    debug(LOG_DEBUG, "send_http_page() : 返回给终端 %s 页面，内容：<%s>%s", r->clientAddr,title,message);
    httpdOutput(r, buffer);
    free(buffer);
}

//>>> liudf added 20160104
//通过定时器自动转向登录网页。
void
http_send_js_redirect(request *r, const char *redir_url)
{
    debug(LOG_DEBUG, "将终端浏览器(自动)重定向到Auth服务器：%s", redir_url);
	struct evbuffer *evb = evbuffer_new ();
	struct evbuffer *evb_redir_url = evbuffer_new();

	evbuffer_add(evb, wifidog_redir_html->front, wifidog_redir_html->front_len);
	evbuffer_add_printf(evb_redir_url, WIFIDOG_REDIR_HTML_CONTENT, redir_url,10);
	evbuffer_add_buffer(evb, evb_redir_url);
	evbuffer_add(evb, wifidog_redir_html->rear, wifidog_redir_html->rear_len);

	int html_length = 0;
	char *redirect_html = evb_2_string(evb, &html_length);

#ifdef	_DEFLATE_SUPPORT_
	if (r->request.deflate) {
		char *deflate_html = NULL;
		int wlen = 0;

		if (deflate_write(redirect_html, html_length, &deflate_html, &wlen, 1) == Z_OK) {
			debug(LOG_DEBUG, "使用Deflate压缩网页。");
			httpdOutputLengthDirect(r, deflate_html, wlen);
		} else
			debug(LOG_INFO, "使用Deflate压缩网页失败。");

		if (deflate_html) free(deflate_html);
	} else
#endif
		httpdOutputLengthDirect(r, redirect_html, html_length);

	_httpd_closeSocket(r);

	free(redirect_html);
	evbuffer_free(evb);
	evbuffer_free(evb_redir_url);
}

void
http_send_apple_redirect(request *r, const char *redir_url)
{
   	httpdPrintf(r, APPLE_REDIRECT_MSG, redir_url);
	_httpd_closeSocket(r);
}

void
http_relay_wisper(request *r)
{
	httpdOutputDirect(r, apple_wisper);
	_httpd_closeSocket(r);
}

void send_http_page_direct(request *r,  char *msg)
{
    debug(LOG_DEBUG, "send_http_page_direct() : 返回给终端 %s 页面", r?r->clientAddr:"空");    
	httpdOutputDirect(r, msg);
	_httpd_closeSocket(r);
}

//<<< liudf added end
