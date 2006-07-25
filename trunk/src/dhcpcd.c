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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include "pathnames.h"
#include "client.h"
#include "signals.h"
#include "udpipgen.h"
#include "logger.h"

int		Daemonized	=	0;
struct in_addr  inform_ipaddr,default_router;
char		*ProgramName	=	NULL;
char            **ProgramEnviron=       NULL;
char		*IfName		=	DEFAULT_IFNAME;
char		*IfNameExt	=	DEFAULT_IFNAME;
int		IfName_len	=	DEFAULT_IFNAME_LEN;
int		IfNameExt_len	=	DEFAULT_IFNAME_LEN;
char		*HostName	=	NULL;
int		HostName_len	=	0;
char		*Cfilename	=	NULL;
unsigned char	*ClassID	=	NULL;
int		ClassID_len	=	0;
unsigned char	*ClientID	=	NULL;
int		ClientID_len	=	0;
void		*(*currState)()	=	&dhcpReboot;
unsigned	LeaseTime	=	DEFAULT_LEASETIME;
int		ReplResolvConf	=	1;
int		ReplNISConf	=	1;
int		ReplNTPConf	=	1;
int		RouteMetric	=	1;
int		SetDomainName	=	0;
int		SetHostName	=	0;
int             BroadcastResp   =       0;
time_t          TimeOut         =	DEFAULT_TIMEOUT;
int 		magic_cookie    =       0;
unsigned short  dhcpMsgSize     =       0;
unsigned        nleaseTime      =       0;
int		TestCase	=	0;
int		SendSecondDiscover	=	0;
int		Window		=	0;
char		*ConfigDir	=	CONFIG_DIR;
int		SetDHCPDefaultRoutes=	1;
int		Persistent	=	0;
int		DownIfaceOnStop	=	1;
int		DoARP		=	1;

char		*etcDir		=	ETC_DIR;
char		resolv_file[128];
char		resolv_file_sv[128];
char		nis_file[128];
char		nis_file_sv[128];
char		ntp_file[128];
char		ntp_file_sv[128];
int		SetFQDNHostName	=	FQDNdisable;

#define STRINGINT(_string, _int) { \
  char *_tmp; \
  long _number = strtol (_string, &_tmp, 0); \
  if (_string[0] == '\0' || *_tmp != '\0' ) \
  goto usage; \
  if ((errno == ERANGE && \
       (_number == LONG_MAX || _number == LONG_MIN )) || \
      (_number > INT_MAX || _number < INT_MIN)) \
  goto usage; \
  _int = _number; \
}

void print_version()
{
  fprintf (stderr, "\
	   DHCP Client Daemon v."VERSION"\n\
	   Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>\n\
	   Copyright (C) January, 1998 Sergei Viznyuk <sv@phystech.com>\n\
	   Copyright (C) 2005 - 2006 Roy Marples <uberlord@gentoo.org>\n\
	   Simon Kelley <simon@thekelleys.org.uk>\n\
	   Location: http://developer.berlios.de/projects/dhcpcd/\n\n");
}

void checkIfAlreadyRunning()
{
  int o;
  char pidfile[64];

  snprintf (pidfile, sizeof (pidfile), PID_FILE_PATH, IfNameExt);
  if ((o = open(pidfile,O_RDONLY)) == -1)
    return;

  close (o);
  logger (LOG_ERR, "already running, if not then delete %s file", pidfile);
  exit (1);
}

int main(int argc, char **argv)
{
  int killFlag = 0;
  int versionFlag = 0;
  int i;
  char *FQDNOption = NULL;
  char c;

  /*
   * Ensure that fds 0, 1, 2 are open, to /dev/null if nowhere else.
   * This way we can close 0, 1, 2 after forking the daemon without clobbering
   * a fd that we are using (such as our sockets). This is necessary if
   * this program is run from init scripts where 0, 1, and/or 2 may be closed.
   */
  i = open ("/dev/null", O_RDWR);
  while ( i < 2 && i >= 0 )
    i = dup (i);

  if (i > 2)
    close (i);

  openlog (PACKAGE, LOG_PID, LOG_LOCAL0);

  if (geteuid())
    {
      logger (LOG_ERR, "not a superuser");
      exit (1);
    }

  while ((c = getopt (argc, argv,
		      "adknopBDHNRSTYl:h:t:i:I:c:s::w:L:G::e:m:F:v:")) != -1)
    switch (c)
      {
      case 'a':
	DoARP = 0;
	break;

      case 'p':
	Persistent = 1;
	break;

      case 'k':
	killFlag = SIGHUP;
	break;

      case 'm':
	STRINGINT(optarg, RouteMetric);
	break;

      case 'n':
	killFlag = SIGALRM;
	break;

      case 'v':
	if ((LogLevel = log_to_level (optarg)) < 0)
	  STRINGINT(optarg, LogLevel);
	break;

      case 'd':
	LogLevel = log_to_level("LOG_DEBUG");
	break;

      case 'D':
	SetDomainName = 1;
	break;

      case 'H':
	SetHostName = 1;
	break;

      case 'R':
	ReplResolvConf = 0;
	break;

      case 'Y':
	ReplNISConf = 0;
	break;

      case 'N':
	ReplNTPConf = 0;
	break;

      case 'V':
	versionFlag=1;
	break;

      case 'c':
	Cfilename = optarg;
	if (Cfilename == NULL || Cfilename[0] == '-')
	  goto usage;
	break;

      case 'L':
	ConfigDir = optarg;
	if (ConfigDir == NULL || ConfigDir[0] != '/')
	  goto usage;
	break;

      case 'e':
	etcDir = optarg;
	if (etcDir == NULL || etcDir[0] != '/')
	  goto usage;
	break;

      case 'i':
	ClassID = (unsigned char *) optarg;
	if (ClassID == NULL || ClassID[0] == '-')
	  goto usage;

	if ((ClassID_len = strlen ((char *)ClassID)) < CLASS_ID_MAX_LEN + 1 )
	  break;

	logger (LOG_ERR, " %s: too long ClassID string: strlen=%d",
		optarg, ClassID_len);
	goto usage;

      case 'I':
	ClientID = (unsigned char *) optarg;
	if (ClientID == NULL || ClientID[0] == '-')
	  goto usage;

	if ((ClientID_len = strlen ((char *) ClientID)) < CLIENT_ID_MAX_LEN + 1)
	  break;
	logger (LOG_ERR,"%s: too long ClientID string: strlen=%d",
		optarg, ClientID_len);
	goto usage;

      case 'h':
	HostName = optarg;
	if (HostName == NULL || HostName[0] == '-')
	  goto usage;

	if ((HostName_len = strlen(HostName) + 1) < HOSTNAME_MAX_LEN )
	  break;

	logger (LOG_ERR,"%s: too long HostName string: strlen=%d\n",
		optarg, HostName_len);
	goto usage;

      case 'F':
	FQDNOption = optarg;
	if ( FQDNOption == NULL || FQDNOption[0] == '-' )
	  goto usage;

	if (strcmp (FQDNOption, "none") == 0)
	  SetFQDNHostName = FQDNnone;
	else if (strcmp (FQDNOption, "ptr") == 0)
	  SetFQDNHostName = FQDNptr;
	else if (strcmp (FQDNOption, "both") == 0)
	  SetFQDNHostName = FQDNboth;
	else
	  goto usage;
	break;

      case 't':
	STRINGINT (optarg, TimeOut);
	if (TimeOut >= 0)
	  break;
	goto usage;

      case 'w':
	STRINGINT (optarg, Window);
	if ( Window >= 0 )
	  break;
	goto usage;

      case 's':
	if (inet_aton (optarg, &inform_ipaddr))
	  {
	    memset (&inform_ipaddr, 0 ,sizeof (inform_ipaddr));
	    currState = &dhcpInform;
	    break;
	  }
	goto usage;

      case 'G':
	SetDHCPDefaultRoutes=0;
	if (inet_aton (optarg, &default_router))
	  {
	    memset(&default_router,0,sizeof(default_router));
	    break;
	  }
	goto usage;

      case 'B':
	BroadcastResp=1;
	break;

      case 'T':
	TestCase = 1;
	break;

      case 'S':
	SendSecondDiscover = 1;
	break;

      case 'l':
	STRINGINT (optarg, LeaseTime);
	if ( LeaseTime > 0 )
	  break;
	goto usage;

      case 'o':
	DownIfaceOnStop = 0;
	break;

      case '?':
	if (isprint (optopt))
	  logger (LOG_ERR, "Unknown option `-%c'", optopt);
	else
	  logger (LOG_ERR, "Unknown option character `\\x%x'", optopt);
	return 1;

usage:
      default:
	print_version();
	fprintf(stderr,
		"Usage: dhcpcd [-adknopBDHNRSTY] [-l leasetime] [-h hostname] [-t timeout]\n\
		[-i vendorClassID] [-I ClientID] [-c filename] [-s [ipaddr]]\n\
		[-w windowsize] [-L ConfigDir] [-G [gateway]] [-e etcDir]\n\
		[-m routeMetric] [-F none|ptr|both]\n\
		[-v logLevel] [interface]\n");
	exit(1);
      }

  if ( optind < argc )
    {
      if ((IfNameExt_len = strlen (argv[optind])) > IFNAMSIZ)
	{
	  logger (LOG_ERR,"%s is too long for an interface name (max=%d)",
		  argv[optind], IFNAMSIZ);
	  goto usage;
	}

      IfNameExt = argv[optind];
      IfName = IfNameExt;
      IfName_len = IfNameExt_len;
      i = 0;
      while (IfNameExt[i])
	if (IfNameExt[i] == ':')
	  {
	    IfName = (char *) malloc (i + 1);
	    memcpy(IfName, IfNameExt, i);
	    IfName[i] = 0;
	    IfName_len = i;
	    break;
	  }
	else
	  i ++;
    }

  ProgramName = argv[0];
  ProgramEnviron = argv;
  umask (022);

  if (killFlag)
    killPid (killFlag);

  if (!TestCase)
    checkIfAlreadyRunning ();

  if (versionFlag)
    print_version ();

  signalSetup ();

  if (mkdir (ConfigDir, S_IRUSR |S_IWUSR |S_IXUSR | S_IRGRP | S_IXGRP
	     | S_IROTH | S_IXOTH) && errno != EEXIST )
    {
      logger(LOG_ERR, "mkdir(\"%s\",0): %s\n", ConfigDir, strerror(errno));
      exit(1);
    }

  if ( mkdir (etcDir, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP
	      | S_IROTH | S_IXOTH) && errno != EEXIST )
    {
      logger(LOG_ERR, "mkdir(\"%s\",0): %s\n", etcDir, strerror(errno));
      exit(1);
    }

  snprintf (resolv_file, sizeof (resolv_file), RESOLV_FILE, etcDir);
  snprintf (resolv_file_sv, sizeof (resolv_file_sv), ""RESOLV_FILE"-%s.sv",
	    etcDir, IfName);
  snprintf (nis_file, sizeof (nis_file), NIS_FILE, etcDir);
  snprintf (nis_file_sv, sizeof (nis_file_sv), ""NIS_FILE"-%s.sv",
	    etcDir, IfName);
  snprintf (ntp_file, sizeof (ntp_file), NTP_FILE, etcDir);
  snprintf (ntp_file_sv, sizeof (ntp_file_sv), ""NTP_FILE"-%s.sv",
	    etcDir, IfName);

  magic_cookie = htonl (MAGIC_COOKIE);
  dhcpMsgSize = htons (sizeof (dhcpMessage) + sizeof (udpiphdr));
  nleaseTime = htonl (LeaseTime);

  if (TimeOut != 0)
    alarm(TimeOut);

  do
    if ((currState = (void *(*)()) currState ()) == NULL )
      exit (1);
  while ( currState != &dhcpBound );

  alarm(0);
#ifdef DEBUG
  writePidFile(getpid());
#else
  if ((i = fork ()))
    {
      writePidFile (i);
      exit (0); /* got into bound state. */
    }
  Daemonized = 1;
  setsid ();
  if ((i = open("/dev/null", O_RDWR, 0)) >= 0)
    {
      (void) dup2(i, STDIN_FILENO);
      (void) dup2(i, STDOUT_FILENO);
      (void) dup2(i, STDERR_FILENO);
      if (i > 2) (void) close (i);
    }
#endif
  chdir ("/");
  do
    currState = (void *(*)()) currState ();
  while ( currState );

  deletePidFile ();
  exit (1);
}
