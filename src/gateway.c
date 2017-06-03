/* vim: set et sw=4 ts=4 sts=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free:Software Foundation; either version 2 of   *
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
  @file gateway.c
  @brief Main loop
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
  @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

/* for strerror() */
#include <string.h>

/* for wait() */
#include <sys/wait.h>

/* for unix socket communication*/
#include <sys/socket.h>
#include <sys/un.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#include "common.h"
#include "httpd.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "gateway.h"
#include "firewall.h"
#include "commandline.h"
#include "auth.h"
#include "http.h"
#include "client_list.h"
#include "wdctl_thread.h"
#include "ping_thread.h"
#include "httpd_thread.h"
#include "util.h"
#include "thread_pool.h"
#include "ipset.h"
#include "https_server.h"
#include "https_common.h"
#include "http_server.h"
#include "mqtt_thread.h"
#include "wd_util.h"

struct evbuffer	*evb_internet_offline_page 		= NULL;
struct evbuffer *evb_authserver_offline_page	= NULL;
struct redir_file_buffer *wifidog_redir_html 	= NULL;

/** XXX Ugly hack
 * We need to remember the thread IDs of threads that simulate wait with pthread_cond_timedwait
 * so we can explicitly kill them in the termination handler
 */
static pthread_t tid_fw_counter 	= 0;
static pthread_t tid_ping 			= 0;
static pthread_t tid_wdctl		 	= 0;
static pthread_t tid_https_server	= 0;
static pthread_t tid_http_server    = 0;
static pthread_t tid_mqtt_server    = 0;
static threadpool_t *pool 			= NULL;

time_t started_time = 0;

/* The internal web server */
httpd * webserver = NULL;

static struct evbuffer *
evhttp_read_file(const char *filename, struct evbuffer *evb)
{
	int fd;
	struct stat stat_info;

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		debug(LOG_CRIT, "Failed to open HTML message file %s: %s", strerror(errno),filename);
		return NULL;
	}

	if (fstat(fd, &stat_info) == -1) {
		debug(LOG_CRIT, "Failed to stat HTML message file: %s", strerror(errno));
		close(fd);
		return NULL;
	}

	evbuffer_add_file(evb, fd, 0, stat_info.st_size);
	close(fd);
	return evb;
}

static void
init_wifidog_msg_html()
{
	s_config *config 			= config_get_config();

	evb_internet_offline_page 	= evbuffer_new();
	if (!evb_internet_offline_page)
		exit(0);

	evb_authserver_offline_page	= evbuffer_new();
	if (!evb_authserver_offline_page)
		exit(0);

    debug(LOG_DEBUG, "init_wifidog_msg_html() : internet_offline_file = %s",config->internet_offline_file);
    debug(LOG_DEBUG, "init_wifidog_msg_html() : authserver_offline_file = %s",config->authserver_offline_file);
	if ( !evhttp_read_file(config->internet_offline_file, evb_internet_offline_page) ||
		 !evhttp_read_file(config->authserver_offline_file, evb_authserver_offline_page)) {
		debug(LOG_ERR, "init_wifidog_msg_html failed, exiting...");
		exit(0);
	}
}

static int
init_wifidog_redir_html(void)
{
    debug(LOG_DEBUG, "init_wifidog_redir_html()");
	s_config *config = config_get_config();
	struct evbuffer *evb_front = NULL;
	struct evbuffer *evb_rear = NULL;
	char	front_file[128] = {0};
	char	rear_file[128] = {0};

    debug(LOG_DEBUG, "init_wifidog_redir_html() : 初始化重定向的网页。");
	wifidog_redir_html = (struct redir_file_buffer *)malloc(sizeof(struct redir_file_buffer));
	if (wifidog_redir_html == NULL) {
		goto err;
	}

	evb_front 	= evbuffer_new();
	evb_rear	= evbuffer_new();
	if (evb_front == NULL || evb_rear == NULL)  {
		goto err;
	}

    debug(LOG_DEBUG, "init_wifidog_redir_html() : 网页名称：%s",config->htmlredirfile);
	snprintf(front_file, 128, "%s.front", config->htmlredirfile);
	snprintf(rear_file, 128, "%s.rear", config->htmlredirfile);
	if (!evhttp_read_file(front_file, evb_front) ||
		!evhttp_read_file(rear_file, evb_rear)) {
		goto err;
	}

	int len = 0;
	wifidog_redir_html->front 		= evb_2_string(evb_front, &len);
	wifidog_redir_html->front_len	= len;
	wifidog_redir_html->rear		= evb_2_string(evb_rear, &len);
	wifidog_redir_html->rear_len	= len;

	if (evb_front) evbuffer_free(evb_front);
	if (evb_rear) evbuffer_free(evb_rear);

    debug(LOG_DEBUG, "init_wifidog_redir_html() : end");
	return 1;
err:
    debug(LOG_ERR, "init_wifidog_redir_html() : 初始化重定向的网页失败。");
    if (evb_front) evbuffer_free(evb_front);
	if (evb_rear) evbuffer_free(evb_rear);
	if (wifidog_redir_html) free(wifidog_redir_html);
	wifidog_redir_html = NULL;
    debug(LOG_DEBUG, "init_wifidog_redir_html() : end");
	return 0;
}

/* Appends -x, the current PID, and NULL to restartargv
 * see parse_commandline in commandline.c for details
 *
 * Why is restartargv global? Shouldn't it be at most static to commandline.c
 * and this function static there? -Alex @ 8oct2006
 */
void
append_x_restartargv(void)
{
    int i;

    for (i = 0; restartargv[i]; i++) ;

    restartargv[i++] = safe_strdup("-x");
    safe_asprintf(&(restartargv[i++]), "%d", getpid());
}

/* @internal
 * @brief During gateway restart, connects to the parent process via the internal socket
 * Downloads from it the active client list
 */
static void
get_clients_from_parent(void)
{
    int sock;
    struct sockaddr_un sa_un;
    s_config *config = NULL;
    char linebuffer[MAX_BUF] = { 0 };
    int len = 0;
    char *running1 = NULL;
    char *running2 = NULL;
    char *token1 = NULL;
    char *token2 = NULL;
    char onechar;
    char *command = NULL;
    char *key = NULL;
    char *value = NULL;
    t_client *client = NULL;

    config = config_get_config();

    debug(LOG_INFO, "连接到父进程下载终端列表。");

    /* Connect to socket */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    /* XXX An attempt to quieten coverity warning about the subsequent connect call:
     * Coverity says: "sock is apssed to parameter that cannot be negative"
     * Although connect expects a signed int, coverity probably tells us that it shouldn't
     * be negative */
    if (sock < 0) {
        debug(LOG_ERR, "不能打开网络连接，终端列表不能下载。错误号：%d，原因：%s", errno,strerror(errno));
        return;
    }
    memset(&sa_un, 0, sizeof(sa_un));
    sa_un.sun_family = AF_UNIX;
    strncpy(sa_un.sun_path, config->internal_sock, (sizeof(sa_un.sun_path) - 1));

    if (connect(sock, (struct sockaddr *)&sa_un, strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
        debug(LOG_ERR, "不能连接父进程，终端列表不能下载。错误号：%d，原因：%s", errno,strerror(errno));
        close(sock);
        return;
    }

    debug(LOG_INFO, "连接父进程，正在下载终端列表。");

    LOCK_CLIENT_LIST();

    command = NULL;
    memset(linebuffer, 0, sizeof(linebuffer));
    len = 0;
    client = NULL;
    /* Get line by line */
    while (read(sock, &onechar, 1) == 1) {
        if (onechar == '\n') {
            /* End of line */
            onechar = '\0';
        }
        linebuffer[len++] = onechar;

        if (!onechar) {
            /* We have a complete entry in linebuffer - parse it */
            debug(LOG_DEBUG, "接收到：[%s]", linebuffer);
            running1 = linebuffer;
            while ((token1 = strsep(&running1, "|")) != NULL) {
                if (!command) {
                    /* The first token is the command */
                    command = token1;
                } else {
                    /* Token1 has something like "foo=bar" */
                    running2 = token1;
                    key = value = NULL;
                    while ((token2 = strsep(&running2, "=")) != NULL) {
                        if (!key) {
                            key = token2;
                        } else if (!value) {
                            value = token2;
                        }
                    }
                }

                if (strcmp(command, "CLIENT") == 0) {
                    /* This line has info about a client in the client list */
                    if (NULL == client) {
                        /* Create a new client struct */
                        client = client_get_new();
                    }
                }

                /* XXX client check to shut up clang... */
                if (key && value && client) {
                    if (strcmp(command, "CLIENT") == 0) {
                        /* Assign the key into the appropriate slot in the connection structure */
                        if (strcmp(key, "ip") == 0) {
                            client->ip = safe_strdup(value);
                        } else if (strcmp(key, "mac") == 0) {
                            client->mac = safe_strdup(value);
                        } else if (strcmp(key, "token") == 0) {
                            client->token = safe_strdup(value);
                        } else if (strcmp(key, "fw_connection_state") == 0) {
                            client->fw_connection_state = atoi(value);
                        } else if (strcmp(key, "fd") == 0) {
                            client->fd = atoi(value);
                        } else if (strcmp(key, "counters_incoming") == 0) {
                            client->counters.incoming_history = (unsigned long long)atoll(value);
                            client->counters.incoming = client->counters.incoming_history;
                            client->counters.incoming_delta = 0;
                        } else if (strcmp(key, "counters_outgoing") == 0) {
                            client->counters.outgoing_history = (unsigned long long)atoll(value);
                            client->counters.outgoing = client->counters.outgoing_history;
                            client->counters.outgoing_delta = 0;
                        } else if (strcmp(key, "counters_last_updated") == 0) {
                            client->counters.last_updated = atol(value);
                        } else {
                            debug(LOG_NOTICE, "从父进程接收到未知内容，%s = %s", key, value);
                        }
                    }
                }
            }

            /* End of parsing this command */
            if (client) {
                client_list_insert_client(client);
            }

            /* Clean up */
            command = NULL;
            memset(linebuffer, 0, sizeof(linebuffer));
            len = 0;
            client = NULL;
        }
    }

    UNLOCK_CLIENT_LIST();
    debug(LOG_INFO, "从父进程下载终端列表成功。");

    close(sock);
}

/**@internal
 * @brief Handles SIGCHLD signals to avoid zombie processes
 *
 * When a child process exits, it causes a SIGCHLD to be sent to the
 * process. This handler catches it and reaps the child process so it
 * can exit. Otherwise we'd get zombie processes.
 */
void
sigchld_handler(int s)
{
    int status;
    pid_t rc;

    debug(LOG_DEBUG, "=  调用SIGCHLD的处理程序，等待子进程退出。");

	do {
    	rc = waitpid(-1, &status, WNOHANG);
        debug(LOG_DEBUG, "=  调用SIGCHLD的处理程序，子进程 %d 退出，返回值(%d)", rc,status);
	} while(rc != (pid_t)0 && rc != (pid_t)-1);
}

/** Exits cleanly after cleaning up the firewall.
 *  Use this function anytime you need to exit after firewall initialization.
 *  @param s Integer that is really a boolean, true means voluntary exit, 0 means error.
 */
void
termination_handler(int s)
{
    static pthread_mutex_t sigterm_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_t self = pthread_self();

    debug(LOG_INFO, "处理程序用于终止捕获的信号[%d]。", s);

    /* Makes sure we only call fw_destroy() once. */
    if (pthread_mutex_trylock(&sigterm_mutex)) {
        debug(LOG_INFO, "另一个线程已经开始全局终止处理程序。 我退出了。");
        pthread_exit(NULL);
    } else {
        debug(LOG_NOTICE, "清理和退出。");
    }

    debug(LOG_INFO, "清理防火墙规则...");
    fw_destroy();

    /* XXX Hack
     * Aparently pthread_cond_timedwait under openwrt prevents signals (and therefore
     * termination handler) from happening so we need to explicitly kill the threads
     * that use that
     */
    if (tid_fw_counter && self != tid_fw_counter) {
        debug(LOG_INFO, "杀掉 fw_counter 线程。");
        pthread_kill(tid_fw_counter, SIGKILL);
    }
    if (tid_ping && self != tid_ping) {
        debug(LOG_INFO, "杀掉 ping 线程。");
        pthread_kill(tid_ping, SIGKILL);
    }
	// liudf added 20160301
	if (tid_wdctl && self != tid_wdctl) {
        debug(LOG_INFO, "杀掉 wdctl 线程。");
		pthread_kill(tid_wdctl, SIGKILL);
	}
	if (tid_https_server && self != tid_https_server) {
		debug(LOG_INFO, "杀掉 https_server 线程。");
		pthread_kill(tid_https_server, SIGKILL);
	}
    if (tid_http_server && self != tid_http_server) {
        debug(LOG_INFO, "杀掉 http_server 线程。");
        pthread_kill(tid_http_server, SIGKILL);
    }
    if (tid_mqtt_server && self != tid_mqtt_server) {
        debug(LOG_INFO, "杀掉 mqtt_server 线程。");
        pthread_kill(tid_mqtt_server, SIGKILL);
    }
	if(pool != NULL) {
		threadpool_destroy(pool, 0);
	}

    debug(LOG_NOTICE, "退出进程...");
    exit(s == 0 ? 1 : 0);
}

/** @internal
 * Registers all the signal handlers
 */
static void
init_signals(void)
{
    struct sigaction sa;

    debug(LOG_DEBUG, "初始化信号处理程序");

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        debug(LOG_ERR, "设置信号SIGCHLD失败，进程将退出。错误码：%d，原因：%s", errno,strerror(errno));
        exit(1);
    }

    /* Trap SIGPIPE */
    /* This is done so that when libhttpd does a socket operation on
     * a disconnected socket (i.e.: Broken Pipes) we catch the signal
     * and do nothing. The alternative is to exit. SIGPIPE are harmless
     * if not desirable.
     */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        debug(LOG_ERR, "设置信号SIGPIPE失败，进程将退出。错误码：%d，原因：%s", errno,strerror(errno));
        exit(1);
    }

    sa.sa_handler = termination_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    /* Trap SIGTERM */
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        debug(LOG_ERR, "设置信号SIGTERM失败，进程将退出。错误码：%d，原因：%s", errno,strerror(errno));
        exit(1);
    }

    /* Trap SIGQUIT */
    if (sigaction(SIGQUIT, &sa, NULL) == -1) {
        debug(LOG_ERR, "设置信号SIGQUIT失败，进程将退出。错误码：%d，原因：%s", errno,strerror(errno));
        exit(1);
    }

    /* Trap SIGINT */
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        debug(LOG_ERR, "设置信号SIGINT失败，进程将退出。错误码：%d，原因：%s", errno,strerror(errno));
        exit(1);
    }
}

static void
wifidog_init()
{
    debug(LOG_DEBUG, "wifidog_init()");

    debug(LOG_DEBUG, "wifidog_init() : ipset_init");
    if(ipset_init() == 0) {
        debug(LOG_ERR, "failed to create IPset control socket: %s");
        exit(1);
    }

    debug(LOG_DEBUG, "wifidog_init() : common_setup");
    common_setup ();              /* Initialize OpenSSL */

    /* Set the time when wifidog started */
    if (!started_time) {
        debug(LOG_DEBUG, "wifidog_init() : 初始化started_time变量");
        started_time = time(NULL);
    } else if (started_time < MINIMUM_STARTED_TIME) {
        debug(LOG_WARNING, "Detected possible clock skew - re-setting started_time");
        started_time = time(NULL);
    }

    // liudf added 20161124
    // read wifidog msg file to memory
    debug(LOG_DEBUG, "wifidog_init() : init_wifidog_msg_html(读取wifidog网页)");
    init_wifidog_msg_html();


    debug(LOG_DEBUG, "wifidog_init() : init_wifidog_redir_html");
    if (!init_wifidog_redir_html()) {
        debug(LOG_ERR, "init_wifidog_redir_html failed, exiting...");
        exit(1);
    }

    debug(LOG_DEBUG, "wifidog_init() : end");
}

static void
refresh_fw()
{
    /* Reset the firewall (if WiFiDog crashed) 重置防火墙（如果WiFiDog崩溃）*/
    debug(LOG_INFO, "# 重置防火墙");
    fw_destroy();

    /* Then initialize it */
    debug(LOG_INFO, "# 初始化防火墙");
    if (!fw_init()) {
        debug(LOG_ERR, "无法初始化防火墙，进程将退出。");
        exit(1);
    }
}

static void
init_web_server(s_config *config)
{
    debug(LOG_DEBUG, "init_web_server()");
    /* Initializes the web server */
    debug(LOG_INFO, "# 创建Web服务器 %s:%d", config->gw_address, config->gw_port);
    if ((webserver = httpdCreate(config->gw_address, config->gw_port)) == NULL) {
        debug(LOG_ERR, "创建Web服务器失败，错误码：%d，原因：%s", errno,strerror(errno));
        exit(1);
    }
    register_fd_cleanup_on_fork(webserver->serverSock);

    debug(LOG_INFO, "# 注册REST服务到Web服务器");
    httpdAddCContent(webserver, "/", "wifidog", 0, NULL, http_callback_wifidog);
    httpdAddCContent(webserver, "/wifidog", "", 0, NULL, http_callback_wifidog);
    httpdAddCContent(webserver, "/wifidog", "about", 0, NULL, http_callback_about);
    httpdAddCContent(webserver, "/wifidog", "status", 0, NULL, http_callback_status);
    httpdAddCContent(webserver, "/wifidog", "auth", 0, NULL, http_callback_auth);
    httpdAddCContent(webserver, "/wifidog", "disconnect", 0, NULL, http_callback_disconnect);

    // liudf added 20160421
    // added temporary pass api
    httpdAddCContent(webserver, "/wifidog", "temporary_pass", 0, NULL, http_callback_temporary_pass);

    httpdSetErrorFunction(webserver, 404, http_callback_404);

    debug(LOG_DEBUG, "init_web_server() : end");
}

static void
create_wifidog_thread(s_config *config)
{
    int result;

    debug(LOG_INFO, "# 创建 https_server 线程，处理HTTPS请求，并且定时解析内置域名来标识网关是否在线。");
    result = pthread_create(&tid_https_server, NULL, (void *)thread_https_server, NULL);
    if (result != 0) {
        debug(LOG_ERR, "创建 https_server 线程失败，将进程退出。");
        termination_handler(0);
    }
    pthread_detach(tid_https_server);

    if (config->work_mode) {
        debug(LOG_INFO, "# 创建 http_server 线程，处理HTTP请求。");
        result = pthread_create(&tid_http_server, NULL, (void *)thread_http_server, NULL);
        if (result != 0) {
            debug(LOG_ERR, "创建 http_server 线程失败，将进程退出。");
            termination_handler(0);
        }
        pthread_detach(tid_http_server);
    }

    debug(LOG_INFO, "# 创建 ping 线程，主动发送心跳(/wifidog/ping)到Auth服务器。");
    result = pthread_create(&tid_ping, NULL, (void *)thread_ping, NULL);
    if (result != 0) {
        debug(LOG_ERR, "创建 ping 线程失败，将进程退出。");
        termination_handler(0);
    }
    pthread_detach(tid_ping);

    debug(LOG_INFO, "# 创建 fw_counter 线程，主动发送统计(/wifidog/auth/?stage=counters)到Auth服务器。");
    result = pthread_create(&tid_fw_counter, NULL, (void *)thread_client_timeout_check, NULL);
    if (result != 0) {
        debug(LOG_ERR, "创建 fw_counter 线程失败，将进程退出。");
        termination_handler(0);
    }
    pthread_detach(tid_fw_counter);

    if(config->pool_mode) {
        int thread_number = config->thread_number;
        int queue_size = config->queue_size;

        debug(LOG_INFO, "# 创建线程池，线程大小：%d，队列：%d", thread_number, queue_size);
        pool = threadpool_create(thread_number, queue_size, 0);
        if(pool == NULL) {
            debug(LOG_ERR, "创建线程池失败，将进程退出。线程大小：%d，队列：%d", thread_number, queue_size);
            termination_handler(0);
        }
    }

#ifdef	_MQTT_SUPPORT_
    debug(LOG_INFO, "# 创建 MQTT 线程，处理MQTT消息。");
    result = pthread_create(&tid_mqtt_server, NULL, (void *)thread_mqtt, config);
    if (result != 0) {
        debug(LOG_ERR, "创建 MQTT 线程失败，将进程退出。");
        termination_handler(0);
    }
    pthread_detach(tid_mqtt_server);
#endif

    debug(LOG_DEBUG, "# 创建 wdctl 线程，处理命令行以及接口消息。");
    result = pthread_create(&tid_wdctl, NULL, (void *)thread_wdctl, (void *)safe_strdup(config->wdctl_sock));
    if (result != 0) {
        debug(LOG_ERR, "创建 wdctl 线程失败，将进程退出。");
        termination_handler(0);
    }
    pthread_detach(tid_wdctl);
}

/**@internal
 * Main execution loop
 */
static void
main_loop(void)
{
    s_config *config = config_get_config();
    request *request_data;
    void **params;
    char task_name[60];

    debug(LOG_NOTICE, "执行初始化(wifidog_init)");
    wifidog_init();

	/* save the pid file if needed */
    if ((!config) && (!config->pidfile))
        save_pid_file(config->pidfile);

    /* If we don't have the Gateway IP address, get it. Can't fail. */
    if (!config->gw_address) {
        debug(LOG_DEBUG, "得到网关(%s)的IP地址(gw_address)。", config->gw_interface);
        if ((config->gw_address = get_iface_ip(config->gw_interface)) == NULL) {
            debug(LOG_ERR, "无法获取 %s 的IP地址，进程将退出。", config->gw_interface);
            exit(1);
        }
        debug(LOG_NOTICE, "网关(%s)的IP地址为：%s", config->gw_interface, config->gw_address);
    }

    /* If we don't have the Gateway ID, construct it from the internal MAC address.
     * "Can't fail" so exit() if the impossible happens. */
    if (!config->gw_id) {
        debug(LOG_DEBUG, "得到网关(%s)的标识(gw_id)，通过Mac地址构造。", config->gw_interface);
        if ((config->gw_id = get_iface_mac(config->gw_interface)) == NULL) {
            debug(LOG_ERR, "无法获取 %s 的Mac地址，进程将退出。", config->gw_interface);
            exit(1);
        }
        debug(LOG_NOTICE, "网关(%s)的标识为：%s", config->gw_interface, config->gw_id);
    }

    debug(LOG_NOTICE, "创建Web服务器。");
    init_web_server(config);

    debug(LOG_NOTICE, "设置防火墙，将所有网络请求拦截。");
    refresh_fw();

    debug(LOG_NOTICE, "创建工作线程。");
	create_wifidog_thread(config);    

    debug(LOG_NOTICE, "Web服务器开始等待终端连接。");
    while (1) {

        request_data = httpdGetConnection(webserver, NULL);

        if (webserver->lastError == -1) {
            /* 中断系统调用 */
            if (NULL != request_data) {
                httpdEndRequest(request_data);
            }
        } else if (webserver->lastError < -1) {
            debug(LOG_ERR, "Web服务器发生异常，异常码：%d，进程将退出。", webserver->lastError);
            termination_handler(0);
		} else if (request_data != NULL && config->pool_mode) {
            //debug(LOG_DEBUG, "main_loop() : 从%s接收到连接，添加到工作队列", request_data->clientAddr);
			params = safe_malloc(2 * sizeof(void *));
            *params = webserver;
            *(params + 1) = request_data;
            
			sprintf(task_name,"TID=%ld",pthread_self());
			int result = threadpool_add(pool, task_name, (void *)thread_httpd, (void *)params, 1);
            if(result != 0) {
            	free(params);
            	httpdEndRequest(request_data);
            	debug(LOG_ERR, "新的网络请求增加到处理线程池失败。返回码：%d", result);
            }
        } else if (request_data != NULL) {
            pthread_t tid;
            //debug(LOG_DEBUG, "从终端 %s 接收到网络连接，产生工作线程。", request_data->clientAddr);
            params = safe_malloc(2 * sizeof(void *));
            *params = webserver;
            *(params + 1) = request_data;

			int result = create_thread(&tid, (void*)thread_httpd, (void *)params);
            if (result != 0) {
                debug(LOG_ERR, "创建一个工作线程失败，进程将退出。返回码：%d", result);
                termination_handler(0);
            }
            pthread_detach(tid);
        } else {
            /* webserver->lastError should be 2 */
            /* XXX We failed an ACL.... No handling because
             * we don't set any... */
        }
    }

    debug(LOG_NOTICE, "进程将退出。");
    /* never reached */
}

/** Reads the configuration file and then starts the main loop */
int
gw_main(int argc, char **argv)
{
    s_config *config = config_get_config();
    config_init();

    parse_commandline(argc, argv);

    debug(LOG_NOTICE, "进程启动中(%s %s)",__DATE__,__TIME__);
    debug(LOG_INFO, "初始化配置文件(%s)",config->configfile);

	/* Initialize the config */
    config_read(config->configfile);
    config_validate();


	debug(LOG_DEBUG, "main() : 初始化连接的客户端的链接列表");
    /* Initializes the linked list of connected clients */
    client_list_init();

    debug(LOG_DEBUG, "main() : 初始化信号");
    /* Init the signals to catch chld/quit/etc */
    init_signals();

    if (restart_orig_pid) {
        //我们重新启动，我们的父母正在等待我们通过套接字进行交谈
        get_clients_from_parent();

        /*
         * At this point the parent will start destroying itself and the firewall. Let it finish it's job before we continue
         */
        while (kill(restart_orig_pid, 0) != -1) {
            debug(LOG_INFO, "等待父进程 %d 退出。", restart_orig_pid);
            s_sleep(1, 0);
        }

        debug(LOG_INFO, "父进程 %d 已经退出，可以继续子进程了。");
    }

    if (config->daemon) {

        debug(LOG_INFO, "进入守护进程模式，创建子进程。");

        switch (safe_fork()) {
        case 0:                /* child */
            debug(LOG_INFO, "子进程开始运行。");
            setsid();
            append_x_restartargv();//增加-x参数，把PID传入
            main_loop();
            break;

        default:               /* parent */
            debug(LOG_INFO, "父进程将退出，由子进程继续。");
            exit(0);
            break;
        }
    } else {
        append_x_restartargv();//增加-x参数，把PID传入

        debug(LOG_DEBUG, "main() : 进入主程序循环");
        main_loop();
    }

    debug(LOG_DEBUG, "main() : end");
    return (0);                 /* never reached */
}
