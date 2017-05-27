/* vim: set et ts=4 sts=4 sw=4 : */
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

/** @file debug.c
    @brief Debug output routines
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include "debug.h"

debugconf_t debugconf = {
    .debuglevel = LOG_DEBUG,
    .log_stderr = 1,
    .log_syslog = 0,
    .syslog_facility = 0
};

/** @internal
Do not use directly, use the debug macro */
void
_debug(const char *filename, int line, int level, const char *format, ...)
{
    char buf[28];
    char fbuf[128];
    char out_buf[4096];
    static unsigned long long GID = 1;

    va_list vlist;
    time_t ts;
    struct tm *my_tm;
    sigset_t block_chld;

    if (debugconf.debuglevel >= level) {
        sigemptyset(&block_chld);
        sigaddset(&block_chld, SIGCHLD);
        sigprocmask(SIG_BLOCK, &block_chld, NULL);

        time(&ts);
        my_tm = localtime(&ts);
        sprintf(buf, "%02d:%02d:%02d",my_tm->tm_hour, my_tm->tm_min, my_tm->tm_sec);
        snprintf(fbuf,sizeof(fbuf),"(%s:%d)",filename, line);

        if (level <= LOG_WARNING) {          
            fprintf(stderr, "[%d]> ", level);
            va_start(vlist, format);
            vfprintf(stderr, format, vlist);
            va_end(vlist);
            fputc('\n', stderr); 
            fflush(stderr);
        } else if (debugconf.log_stderr) {
            fprintf(stderr,  "[%d]> ", level);
            va_start(vlist, format);
            vfprintf(stderr, format, vlist);
            va_end(vlist);
            fputc('\n', stderr);
            fflush(stderr);
        }

        if (debugconf.log_syslog) 
        {
            int ilen = snprintf(out_buf,sizeof(out_buf),"%d|%s|%d|%llu|>",pthread_self(),filename, line, GID);
            ilen = (ilen>sizeof(out_buf)?sizeof(out_buf):ilen);
            
            openlog("wifidog",LOG_PID, debugconf.syslog_facility);
            
            va_start(vlist, format);
            ilen = ilen + vsnprintf(out_buf+ilen, sizeof(out_buf)-ilen, format, vlist); 
            //vsyslog(level, format, vlist);
            va_end(vlist);

            int i=0;
            while (i<=ilen)
            {
                if( *(out_buf+i)=='\r' )
                {
                    *(out_buf+i)='~';
                } else if( *(out_buf+i)=='\n' )
                {
                    *(out_buf+i)='~';
                }
                i++;
            }            
            
            syslog(level,"%s",out_buf);
            closelog();

            //printf("%s\n",out_buf);
            GID++;
        }
        
        sigprocmask(SIG_UNBLOCK, &block_chld, NULL);
    }
}
