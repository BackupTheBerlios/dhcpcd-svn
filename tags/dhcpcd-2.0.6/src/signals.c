/*
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 * Copyright (C) January, 1998 Sergei Viznyuk <sv@phystech.com>
 * Copyright (C) 2005 - 2006 Roy Marples <uberlord@gentoo.org>
 * Copyright (C) 2005 - 2006 Simon Kelley <simon@thekelleys.org.uk> 
 * 
 * dhcpcd is an RFC2131 and RFC1541 compliant DHCP client daemon.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "pathnames.h"
#include "client.h"
#include "logger.h"

extern char		*ProgramName;
extern char		*IfNameExt;
extern char		*ConfigDir;
extern int              Persistent;
extern jmp_buf		env;
extern void		*(*currState)();
extern int		execOnStop;

jmp_buf			jmpTerm;

/*****************************************************************************/
void killPid(sig)
int sig;
{
  FILE *fp;
  pid_t pid;
  char pidfile[64];
  snprintf(pidfile,sizeof(pidfile),PID_FILE_PATH,IfNameExt);
  fp=fopen(pidfile,"r");
  if ( fp == NULL ) goto ntrn;
  fscanf(fp,"%u",&pid);
  fclose(fp);
  if ( kill(pid,sig) )
    {
      unlink(pidfile);
ntrn: if ( sig == SIGALRM ) return;
      logger(LOG_ERR,"%s: not running", ProgramName);
    }
  exit(0);
}
/*****************************************************************************/
void writePidFile(pid_t pid)
{
  FILE *fp;
  char pidfile[64];
  snprintf(pidfile,sizeof(pidfile),PID_FILE_PATH,IfNameExt);
  fp=fopen(pidfile,"w");
  if ( fp == NULL )
    {
      logger(LOG_ERR, "writePidFile: fopen: %s", strerror(errno));
      exit(1);
    }
  fprintf(fp,"%u\n",pid);
  fclose (fp);
}
/*****************************************************************************/
void deletePidFile()
{
  char pidfile[64];
  snprintf(pidfile,sizeof(pidfile),PID_FILE_PATH,IfNameExt);
  unlink(pidfile);
}
/*****************************************************************************/
void sigHandler(sig)
int sig;
{
  if( sig == SIGCHLD )
    {
      waitpid(-1,NULL,WNOHANG);
      return;
    }
  if ( sig == SIGALRM )
    {
      if ( currState == &dhcpBound )
        siglongjmp(env,1); /* this timeout is T1 */
      else
        {
          if ( currState == &dhcpRenew )
            siglongjmp(env,2); /* this timeout is T2 */
          else
	    {
	      if ( currState == &dhcpRebind )
	        siglongjmp(env,3);  /* this timeout is dhcpIpLeaseTime */
	      else
		{
		  if ( currState == &dhcpReboot )
		    siglongjmp(env,4);  /* failed to acquire the same IP address */
		  else
	            logger(LOG_ERR, "timed out waiting for a valid DHCP server response");
		}
	    }
        }
    }
  else
    {
      if ( sig == SIGHUP ) 
	{
	  dhcpRelease();
	  /* allow time for final packets to be transmitted before shutting down     */
	  /* otherwise 2.0 drops unsent packets. fixme: find a better way than sleep */
	  sleep(1);
	}
	logger(LOG_ERR, "terminating on signal %d",sig);
    }
  if (sig == SIGTERM) siglongjmp(jmpTerm, 1);
  if (!Persistent) dhcpStop();
  deletePidFile();

  /* Exit with 0 if we were told to quit, otherwise the SIG code */
  if (sig == SIGQUIT || sig == SIGINT || sig == SIGHUP)
    exit(0);
  else
    exit(sig);
}
/*****************************************************************************/
void signalSetup()
{
  int i;
  struct sigaction action;
  sigaction(SIGHUP,NULL,&action);
  action.sa_handler= &sigHandler;
  action.sa_flags = 0;
  for (i=1;i<16;i++) sigaction(i,&action,NULL);
  sigaction(SIGCHLD,&action,NULL);

  /* We do this so that we can call external programs safely from a SIGTERM */
  if ( sigsetjmp(jmpTerm, 1) ) {
    if (!Persistent) dhcpStop();
    deletePidFile();
    exit(0);
  }
}