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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <resolv.h>
#include <netdb.h>

#include "arp.h"
#include "config.h"
#include "pathnames.h"
#include "client.h"
#include "logger.h"

extern  int                     DebugFlag;
extern  int                     dhcpSocket;
extern  int                     udpFooSocket;
extern  int                     prev_ip_addr;
extern  int                     Window;
extern  int                     SetDHCPDefaultRoutes;
extern  int                     TestCase;
extern  int                     SetDomainName;
extern  int                     SetHostName;
extern  int                     ReplResolvConf;
extern  int                     ReplNISConf;
extern  int                     ReplNTPConf;
extern  int                     RouteMetric;
extern  int                     IfName_len,IfNameExt_len;
extern  char                    *IfName,*IfNameExt,*Cfilename,*ConfigDir;
extern  char                    **ProgramEnviron;
extern  unsigned char           ClientHwAddr[ETH_ALEN],*ClientID;
extern  struct in_addr          default_router;
extern  dhcpInterface           DhcpIface;
extern  dhcpOptions             DhcpOptions;

extern  char                    resolv_file[128];
extern  char                    resolv_file_sv[128];
extern  char                    ntp_file[128];
extern  char                    ntp_file_sv[128];
extern  char                    nis_file[128];
extern  char                    nis_file_sv[128];

extern  int                     SetFQDNHostName;

char	hostinfo_file[128];
int	resolv_renamed=0; 
int	yp_renamed=0;
int	ntp_renamed=0;  
int     have_info=0; /* set once we have written the hostinfo file */

/* Note: Legths initialised to negative to allow us to distinguish between "empty" and "not set" */
char InitialHostName[HOSTNAME_MAX_LEN];
int InitialHostName_len=-1;
char InitialDomainName[HOSTNAME_MAX_LEN];
int InitialDomainName_len=-1;

char *cleanmetas(char *cstr) /* this is to clean single quotes out of DHCP strings */
{
  register char *c=cstr;
  
  do
    if (*c == 39)
      *c = ' ';
  while (*c++);
  
  return cstr;
}

void execute_on_change(char *prm)
{
  if (!have_info)
    return;

  if (fork () == 0)
      {
	char *argc[4], exec_on_change[128];

	if (Cfilename)
	  snprintf (exec_on_change, sizeof (exec_on_change), Cfilename);
	else
	  snprintf(exec_on_change, sizeof (exec_on_change), EXEC_ON_CHANGE);
	
	argc[0] = exec_on_change;
	argc[1] = hostinfo_file;
	argc[2] = prm;
	argc[3] = NULL;
	logger (LOG_DEBUG, "about to exec \"%s %s %s\"", exec_on_change,
	       hostinfo_file, prm);
	
	if (execve (exec_on_change, argc, ProgramEnviron) && 
	     (errno != ENOENT || Cfilename))
	  logger (LOG_ERR, "error executing \"%s %s %s\": %s",
		 exec_on_change, hostinfo_file, prm, strerror (errno));
	
	exit(0);
      }
}

unsigned long getgenmask(unsigned long ip_in)	/* this is to guess genmask	*/
{
  unsigned long t, p = ntohl (ip_in);
  
  if (IN_CLASSA (p))
    t = ~IN_CLASSA_NET;
  else
    {
      if (IN_CLASSB (p))
	t = ~IN_CLASSB_NET;
      else
	{
	  if (IN_CLASSC (p))
	    t = ~IN_CLASSC_NET;
	  else
	    t = 0;
	}
    }
  while (t & p) t >>= 1;
  return htonl (~t);
}

int setDefaultRoute(char *route_addr)
{
  struct rtentry rtent;
  struct sockaddr_in *p;

  memset (&rtent, 0, sizeof (struct rtentry));
  p = (struct sockaddr_in *) &rtent.rt_dst;
  p->sin_family	= AF_INET;
  p->sin_addr.s_addr = 0;
  p = (struct sockaddr_in *) &rtent.rt_gateway;
  p->sin_family = AF_INET;
  memcpy (&p->sin_addr.s_addr, route_addr,4);
  p = (struct sockaddr_in *) &rtent.rt_genmask;
  p->sin_family = AF_INET;
  p->sin_addr.s_addr = 0;
  rtent.rt_dev = IfNameExt;
  rtent.rt_metric = RouteMetric;
  rtent.rt_window = Window;
  rtent.rt_flags = RTF_UP | RTF_GATEWAY | (Window ? RTF_WINDOW : 0);
  
  if (ioctl( dhcpSocket, SIOCADDRT, &rtent) == -1)
    {
      if (errno == ENETUNREACH)    /* possibly gateway is over the bridge */
	{                            /* try adding a route to gateway first */
	  memset (&rtent, 0, sizeof (struct rtentry));
	  p = (struct sockaddr_in *) &rtent.rt_dst;
	  p->sin_family	= AF_INET;
	  memcpy (&p->sin_addr.s_addr, route_addr, 4);
	  p = (struct sockaddr_in *) &rtent.rt_gateway;
	  p->sin_family = AF_INET;
	  p->sin_addr.s_addr = 0;
	  p = (struct sockaddr_in *) &rtent.rt_genmask;
	  p->sin_family = AF_INET;
	  p->sin_addr.s_addr = 0xffffffff;
	  rtent.rt_dev = IfNameExt;
	  rtent.rt_metric = RouteMetric;
	  rtent.rt_flags = RTF_UP|RTF_HOST;
	  
	  if (ioctl( dhcpSocket, SIOCADDRT, &rtent) == 0)
	    {
	      memset (&rtent, 0, sizeof (struct rtentry));
	      p = (struct sockaddr_in *) &rtent.rt_dst;
	      p->sin_family = AF_INET;
	      p->sin_addr.s_addr = 0;
	      p = (struct sockaddr_in *) &rtent.rt_gateway;
	      p->sin_family = AF_INET;
	      memcpy (&p->sin_addr.s_addr, route_addr, 4);
	      p = (struct sockaddr_in *) &rtent.rt_genmask;
	      p->sin_family = AF_INET;
	      p->sin_addr.s_addr = 0;
	      rtent.rt_dev = IfNameExt;
	      rtent.rt_metric = RouteMetric;
	      rtent.rt_window = Window;
	      rtent.rt_flags = RTF_UP |RTF_GATEWAY | (Window ? RTF_WINDOW : 0);
	      if (ioctl (dhcpSocket, SIOCADDRT, &rtent) == -1 && errno != EEXIST)
		{
		  logger (LOG_ERR,"dhcpConfig: ioctl SIOCADDRT: %s",
			 strerror (errno));
		  return -1;
		}
	    }
	}
      else
	{
	  if (errno != EEXIST)
	    {
	      logger (LOG_ERR, "dhcpConfig: ioctl SIOCADDRT: %s",
		      strerror (errno));
	      return -1;
	    }
	}
    }
  
  return 0;
}

int islink(char *file)
{
  char b[1];
  
  int n = readlink (file, b, 1);
  
  return (n == -1 ? 0 : 1);
}

int addRoute(char *network, char *gateway, char *genmask)
{
  struct rtentry rtent;
  struct sockaddr_in *netp; 
  struct sockaddr_in *genp; 
  struct sockaddr_in *gwp;

  if (!network || !gateway || !genmask)
    return -1;

  memset (&rtent, 0, sizeof (struct rtentry));

  netp = (struct sockaddr_in *) &rtent.rt_dst;
  netp->sin_family = AF_INET;
  memcpy (&netp->sin_addr.s_addr, network, 4);

  genp = (struct sockaddr_in *) &rtent.rt_genmask;
  genp->sin_family = AF_INET;
  memcpy (&genp->sin_addr.s_addr, genmask, 4);
 
  gwp = (struct sockaddr_in *) &rtent.rt_gateway;
  gwp->sin_family = AF_INET;
  memcpy (&gwp->sin_addr.s_addr, gateway, 4);
  
  rtent.rt_flags = RTF_UP | RTF_GATEWAY;
  if (genp->sin_addr.s_addr == 0xffffffff)
    rtent.rt_flags |= RTF_HOST;

  rtent.rt_dev = IfNameExt;
  rtent.rt_metric = RouteMetric;

  char *netd = strdup (inet_ntoa (netp->sin_addr));
  char *gend = strdup (inet_ntoa (genp->sin_addr));
  logger (LOG_INFO, "adding route to %s (%s) via %s", netd, gend,
	  inet_ntoa(gwp->sin_addr));
  if (netd)
    free (netd);
  if (gend)
    free (gend);

  if (ioctl (dhcpSocket, SIOCADDRT, &rtent) && errno != EEXIST)
    {
      logger (LOG_ERR, "dhcpConfig: ioctl SIOCADDRT: %s", strerror (errno));
      return -1;
    }

  return 0;
}

int dhcpConfig()
{
  int i;
  FILE *f = NULL;
  char hostinfo_file_old[128];
  struct ifreq ifr;
  struct rtentry rtent;
  struct sockaddr_in *p = (struct sockaddr_in *) &(ifr.ifr_addr);
  struct hostent *hp = NULL;
  char *dname = NULL;
  int dname_len = 0;
  char network[5], gateway[5], genmask[5];
  unsigned long gn;

  if (TestCase)
    goto tsc;
 
  logger (LOG_INFO,"setting ip address to %u.%u.%u.%u on %s",
	 ((unsigned char *) &DhcpIface.ciaddr)[0],
	 ((unsigned char *) &DhcpIface.ciaddr)[1],
	 ((unsigned char *) &DhcpIface.ciaddr)[2],
	 ((unsigned char *) &DhcpIface.ciaddr)[3], IfNameExt);
  
  memset (&ifr, 0, sizeof (struct ifreq));
  memcpy (ifr.ifr_name, IfNameExt, IfNameExt_len);
  p->sin_family = AF_INET;
  p->sin_addr.s_addr = DhcpIface.ciaddr;
  errno = 0;
  if (ioctl (dhcpSocket,SIOCSIFADDR, &ifr) == -1)  /* setting IP address */
    {
      logger (LOG_ERR, "dhcpConfig: ioctl SIOCSIFADDR: %s", strerror (errno));
      return -1;
    }
  
  memcpy (&p->sin_addr.s_addr, DhcpOptions.val[subnetMask], 4);
  if (ioctl (dhcpSocket, SIOCSIFNETMASK, &ifr) == -1)  /* setting netmask */
    {
      p->sin_addr.s_addr = 0xffffffff; /* try 255.255.255.255 */
      if (ioctl (dhcpSocket, SIOCSIFNETMASK, &ifr) == -1)
	{
	  logger (LOG_ERR, "dhcpConfig: ioctl SIOCSIFNETMASK: %s",
		  strerror (errno));
	  return -1;
	}
    }
  
  memcpy (&p->sin_addr.s_addr, DhcpOptions.val[broadcastAddr], 4);
  if (ioctl (dhcpSocket, SIOCSIFBRDADDR, &ifr) == -1) /* setting broadcast address */
    logger (LOG_ERR, "dhcpConfig: ioctl SIOCSIFBRDADDR: %s", strerror (errno));

  /* setting local route
   * need to delete kernel added route on newer kernels */
  memset (&rtent, 0 ,sizeof (struct rtentry));
  p = (struct sockaddr_in *) &rtent.rt_dst;
  p->sin_family = AF_INET;
  memcpy (&p->sin_addr.s_addr, DhcpOptions.val[subnetMask], 4);
  
  p->sin_addr.s_addr &=	DhcpIface.ciaddr;
  p = (struct sockaddr_in *) &rtent.rt_gateway;
  p->sin_family = AF_INET;
  p->sin_addr.s_addr = 0;
  p = (struct sockaddr_in *) &rtent.rt_genmask;
  p->sin_family = AF_INET;
  memcpy (&p->sin_addr.s_addr, DhcpOptions.val[subnetMask], 4);
  
  rtent.rt_dev = IfName;
  rtent.rt_metric = 1;
  rtent.rt_flags = RTF_UP;
  
  if (ioctl (dhcpSocket, SIOCDELRT, &rtent))
    logger (LOG_ERR, "dhcpConfig: ioctl SIOCDELRT: %s", strerror (errno));

  /* Now add our new default route for the network */
  memset (&rtent, 0, sizeof (struct rtentry));
  p = (struct sockaddr_in *)&rtent.rt_dst;
  p->sin_family	= AF_INET;
  memcpy (&p->sin_addr.s_addr, DhcpOptions.val[subnetMask], 4);
  
  p->sin_addr.s_addr &= DhcpIface.ciaddr;
  p = (struct sockaddr_in *) &rtent.rt_gateway;
  p->sin_family = AF_INET;
  p->sin_addr.s_addr = 0;
  p = (struct sockaddr_in *) &rtent.rt_genmask;
  p->sin_family	= AF_INET;
  memcpy (&p->sin_addr.s_addr, DhcpOptions.val[subnetMask], 4);
  
  rtent.rt_dev = IfName;
  rtent.rt_metric = RouteMetric;
  rtent.rt_flags = RTF_UP;
  if (ioctl (dhcpSocket,SIOCADDRT,&rtent) && errno != EEXIST)
    logger (LOG_ERR, "dhcpConfig: ioctl SIOCADDRT: %s", strerror (errno));

  memset (&network, 0, 5);
  memset (&genmask, 0, 5);
  memset (&gateway, 0, 5);
  if (DhcpOptions.len[classlessStaticRoutes] > 0)
    {
      for (i = 0; i < DhcpOptions.len[classlessStaticRoutes]; i += 12)
	{
	  memcpy (&network, DhcpOptions.val[classlessStaticRoutes] + i, 4);
	  memcpy (&genmask, DhcpOptions.val[classlessStaticRoutes] + i + 4, 4);
	  memcpy (&gateway, DhcpOptions.val[classlessStaticRoutes] + i + 8, 4);
	  addRoute (network, gateway, genmask);
	}
    }
  else
    {
      for (i = 0; i < DhcpOptions.len[staticRoute]; i += 8)
	{
	  memcpy (&network, DhcpOptions.val[staticRoute] + i, 4);
	  memcpy (&gateway, DhcpOptions.val[staticRoute] + i + 4, 4);
	  /* Work out the genmask */
	  memcpy (&gn, DhcpOptions.val[staticRoute] + i, 4);
	  gn = getgenmask(gn);
	  addRoute (network, gateway, (char *) &gn);
	}
    }

  if (SetDHCPDefaultRoutes)
    {
      if (DhcpOptions.len[routersOnSubnet] > 3)
	for (i = 0; i <DhcpOptions.len[routersOnSubnet]; i += 4)
	  setDefaultRoute (DhcpOptions.val[routersOnSubnet] + i);
    }
  else
    if (default_router.s_addr > 0)
      setDefaultRoute ((char *) &(default_router.s_addr));

  arpInform ();
  
  if (ReplResolvConf && (DhcpOptions.len[domainName] || DhcpOptions.len[dns]))
    {
      if (!islink (resolv_file))
	resolv_renamed = 1 + rename (resolv_file, resolv_file_sv);

      struct stat buf;
      int resolvconf = 0;
      if (!stat ("/sbin/resolvconf", &buf))
	{
	logger (LOG_DEBUG, "sending DNS information to resolvconf");
	resolvconf = 1;
	char *arg = malloc (strlen ("/sbin/resolvconf -a ")
			    + strlen (IfName) + 1);
	snprintf(arg, strlen("/sbin/resolvconf -a ") +strlen (IfName) + 1,
		 "/sbin/resolvconf -a %s", IfName);
	f = popen (arg,"w");
	free (arg);
	
	if (!f)
	  logger (LOG_ERR, "dhcpConfig: popen: %s", strerror (errno));
      } else {
	if (! (f = fopen( resolv_file, "w")))
	  logger (LOG_ERR, "dhcpConfig: fopen %s: %s", resolv_file,
		  strerror (errno));
      }
      
      if (f) 
	{
	  int i;
	  fprintf (f, "# Generated by dhcpcd for interface %s\n", IfName);
	  if (DhcpOptions.len[dnsSearchPath])
	    fprintf (f, "search %s\n", (char *) DhcpOptions.val[dnsSearchPath]);
	  else if (DhcpOptions.len[domainName]) {
	    fprintf (f, "search %s\n", (char *) DhcpOptions.val[domainName]);
	  }

	  for (i = 0; i <DhcpOptions.len[dns]; i += 4)
	    fprintf (f, "nameserver %u.%u.%u.%u\n",
		    ((unsigned char *) DhcpOptions.val[dns])[i],
		    ((unsigned char *) DhcpOptions.val[dns])[i + 1],
		    ((unsigned char *) DhcpOptions.val[dns])[i + 2],
		    ((unsigned char *) DhcpOptions.val[dns])[i + 3]);

	  if (resolvconf)
	    {
	      logger (LOG_DEBUG, "resolvconf completed");
	      pclose (f);
	    }
	  else
	    fclose (f);
	}

      /* moved the next section of code from before to after we've created
       * resolv.conf. See below for explanation. <poeml@suse.de>
       * res_init() is normally called from within the first function of the
       * resolver which is called. Here, we want resolv.conf to be
       * reread. Otherwise, we won't be able to find out about our hostname,
       * because the resolver won't notice the change in resolv.conf */
      (void) res_init();
    }
  
  if (ReplNISConf && (DhcpOptions.len[nisDomainName] || DhcpOptions.len[nisServers]))
    {
      if (!islink (nis_file))
	yp_renamed = 1 + rename (nis_file, nis_file_sv);
      
      if ((f = fopen(nis_file, "w")))
	{
	  int i;
	  char *prefix = NULL;
	  fprintf (f, "# Generated by dhcpcd for interface %s\n", IfName);
	  if (DhcpOptions.len[nisDomainName])
	    {
	    if (DhcpOptions.len[nisServers])
	      {
	      prefix = (char *) malloc (DhcpOptions.len[nisDomainName] + 15);
	      sprintf (prefix, "domain %s server",
		       (char *) DhcpOptions.val[nisDomainName]);
	    }
	    else
	      fprintf (f, "domain %s broadcast\n",
		       (char *)DhcpOptions.val[nisDomainName]);
	  }
	  else
	    prefix = strdup("ypserver");

	  for (i = 0; i <DhcpOptions.len[nisServers]; i += 4)
	    fprintf (f, "%s %u.%u.%u.%u\n", prefix,
		    ((unsigned char *) DhcpOptions.val[nisServers])[i],
		    ((unsigned char *) DhcpOptions.val[nisServers])[i+1],
		    ((unsigned char *) DhcpOptions.val[nisServers])[i+2],
		    ((unsigned char *) DhcpOptions.val[nisServers])[i+3]);

	  fclose (f);

	  if (prefix)
	    free (prefix);
	}
      else
	logger (LOG_ERR, "dhcpConfig: fopen %s: %s", nis_file, strerror (errno));
    }
  
  if (ReplNTPConf && DhcpOptions.len[ntpServers] >= 4)
    {
      if (!islink (ntp_file))
	ntp_renamed = 1 + rename (ntp_file, ntp_file_sv);
      
      if ((f = fopen (ntp_file, "w")))
	{
	  int i;
	  char addr[4*3+3*1+1];
	  
	  fprintf (f, "# Generated by dhcpcd for interface %s\n", IfName);
	  fprintf (f, "restrict default noquery notrust nomodify\n");
	  fprintf (f, "restrict 127.0.0.1\n");

	  for (i = 0; i < DhcpOptions.len[ntpServers]; i += 4)
	    {
	      snprintf (addr ,sizeof(addr) ,"%u.%u.%u.%u",
		       ((unsigned char *) DhcpOptions.val[ntpServers])[i],
		       ((unsigned char *) DhcpOptions.val[ntpServers])[i + 1],
		       ((unsigned char *) DhcpOptions.val[ntpServers])[i + 2],
		       ((unsigned char *) DhcpOptions.val[ntpServers])[i + 3]);
	      fprintf (f, "restrict %s nomodify notrap noquery\nserver %s\n",
		       addr, addr);
	    }

	  fprintf (f, "driftfile /etc/ntp.drift\n");
	  fprintf (f, "logfile /var/log/ntp.log\n");
	  fclose (f);
	}
      else
	logger (LOG_ERR, "dhcpConfig: fopen %s: %s", ntp_file, strerror (errno));
    }
  
  if (SetHostName && !DhcpOptions.len[hostName])
    {
      hp = gethostbyaddr((char *) &DhcpIface.ciaddr,
		       sizeof (DhcpIface.ciaddr), AF_INET);
      if (hp)
	{
	  dname = hp->h_name;
	  while (*dname > 32)
	    dname++;
	  dname_len=dname-hp->h_name;
	  
	  DhcpOptions.val[hostName] = (char *) malloc (dname_len+1);
	  DhcpOptions.len[hostName] = dname_len;
	  memcpy ((char *)DhcpOptions.val[hostName], hp->h_name, dname_len);
	  ((char *)DhcpOptions.val[hostName])[dname_len] = 0;
	  DhcpOptions.num++;
	}
    }
  
  if (InitialHostName_len < 0)
    {
      gethostname (InitialHostName, sizeof (InitialHostName));
      InitialHostName_len = strlen (InitialHostName);
    }
  
  if (SetHostName || InitialHostName_len == 0
      || !strcmp (InitialHostName, "(none)"))
    {
      if (DhcpOptions.len[hostName])
	{
	  logger (LOG_DEBUG, "orig hostname = %s", InitialHostName);
	  SetHostName = 1;
	  sethostname (DhcpOptions.val[hostName], DhcpOptions.len[hostName]);
	  logger (LOG_INFO, "new hostname = %s",
		 (char *) DhcpOptions.val[hostName]);
	}
    }
  
  if (SetDomainName)
    {
      if (InitialDomainName_len < 0 &&
	  getdomainname (InitialDomainName, sizeof (InitialDomainName)) == 0)
	{
	  InitialDomainName_len = strlen (InitialDomainName);
	  logger (LOG_INFO, "orig domainname = %s", InitialDomainName);
	}
	  if (!DhcpOptions.len[domainName])
	    {
	      if (!hp)
		hp = gethostbyaddr ((char *) &DhcpIface.ciaddr,
				 sizeof(DhcpIface.ciaddr), AF_INET);
	      if (hp)
		{
		  dname = hp->h_name;
		  while (*dname > 32)
		    if (*dname == '.')
		      {
			dname++;
			break;
		      }
		    else
		      dname++;
		  dname_len = strlen (dname);
		  
		  if (dname_len)
		    {
		      DhcpOptions.val[domainName] =
		       (char *) malloc (dname_len+1);
		      DhcpOptions.len[domainName] = dname_len;
		      
		      memcpy ((char *) DhcpOptions.val[domainName],
			     dname, dname_len);
		      ((char *) DhcpOptions.val[domainName])[dname_len] = 0;
		      DhcpOptions.num++;
		    }
		}
	    }
	  if (DhcpOptions.len[domainName])
	    {
	      setdomainname (DhcpOptions.val[domainName],
			     DhcpOptions.len[domainName]);
	      logger (LOG_DEBUG, "your domainname = %s\n",
		     (char *) DhcpOptions.val[domainName]);
	    }
    }
  
tsc:
  memset (DhcpIface.version, 0, sizeof (DhcpIface.version));
  strncpy (DhcpIface.version, VERSION, sizeof (DhcpIface.version));
  snprintf (hostinfo_file_old, sizeof (hostinfo_file_old), DHCP_CACHE_FILE,
	    CONFIG_DIR, IfNameExt);
  i = open (hostinfo_file_old, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR +S_IWUSR);
  if ( i == -1 ||
       write (i, (char *) &DhcpIface, sizeof (dhcpInterface)) == -1 ||
       close (i) == -1 )
    logger (LOG_ERR," dhcpConfig: open/write/close: %s", strerror (errno));
  
  snprintf (hostinfo_file, sizeof (hostinfo_file),
	    DHCP_HOSTINFO, ConfigDir, IfNameExt);
  snprintf (hostinfo_file_old, sizeof(hostinfo_file_old),
	    ""DHCP_HOSTINFO".old", ConfigDir, IfNameExt);
  
  rename(hostinfo_file,hostinfo_file_old);
  
  if ((f = fopen (hostinfo_file, "w")))
    {
      int b, c;
      memcpy (&b, DhcpOptions.val[subnetMask], 4);
      c = DhcpIface.ciaddr & b;
      fprintf (f, "IPADDR=%u.%u.%u.%u\nNETMASK=\%u.%u.%u.%u\n"
	      "NETWORK=%u.%u.%u.%u\nBROADCAST=\%u.%u.%u.%u",
	      ((unsigned char *) &DhcpIface.ciaddr)[0],
	      ((unsigned char *) &DhcpIface.ciaddr)[1],
	      ((unsigned char *) &DhcpIface.ciaddr)[2],
	      ((unsigned char *) &DhcpIface.ciaddr)[3],
	      ((unsigned char *) DhcpOptions.val[subnetMask])[0],
	      ((unsigned char *) DhcpOptions.val[subnetMask])[1],
	      ((unsigned char *) DhcpOptions.val[subnetMask])[2],
	      ((unsigned char *) DhcpOptions.val[subnetMask])[3],
	      ((unsigned char *) &c)[0],
	      ((unsigned char *) &c)[1],
	      ((unsigned char *) &c)[2],
	      ((unsigned char *) &c)[3],
	      ((unsigned char *) DhcpOptions.val[broadcastAddr])[0],
	      ((unsigned char *) DhcpOptions.val[broadcastAddr])[1],
	      ((unsigned char *) DhcpOptions.val[broadcastAddr])[2],
	      ((unsigned char *) DhcpOptions.val[broadcastAddr])[3]);

      if (DhcpOptions.len[classlessStaticRoutes])
	{
	  fprintf (f, "\nCLASSLESSROUTE=%u.%u.%u.%u,%u.%u.%u.%u,%u.%u.%u.%u",
		  ((unsigned char *) DhcpOptions.val[classlessStaticRoutes])[0],
		  ((unsigned char *) DhcpOptions.val[classlessStaticRoutes])[1],
		  ((unsigned char *) DhcpOptions.val[classlessStaticRoutes])[2],
		  ((unsigned char *) DhcpOptions.val[classlessStaticRoutes])[3],
		  ((unsigned char *) DhcpOptions.val[classlessStaticRoutes])[4],
		  ((unsigned char *) DhcpOptions.val[classlessStaticRoutes])[5],
		  ((unsigned char *) DhcpOptions.val[classlessStaticRoutes])[6],
		  ((unsigned char *) DhcpOptions.val[classlessStaticRoutes])[7],
		  ((unsigned char *) DhcpOptions.val[classlessStaticRoutes])[8],
		  ((unsigned char *) DhcpOptions.val[classlessStaticRoutes])[9],
		  ((unsigned char *)
		   DhcpOptions.val[classlessStaticRoutes])[10],
		  ((unsigned char *)
		   DhcpOptions.val[classlessStaticRoutes])[11]);
	  for (i = 12;i < DhcpOptions.len[classlessStaticRoutes]; i += 12)
	    fprintf (f, ",%u.%u.%u.%u,%u.%u.%u.%u,%u.%u.%u.%u",
		    ((unsigned char *)
		     DhcpOptions.val[classlessStaticRoutes])[i],
		    ((unsigned char *)
		     DhcpOptions.val[classlessStaticRoutes])[1 + i],
		    ((unsigned char *)
		     DhcpOptions.val[classlessStaticRoutes])[2 + i],
		    ((unsigned char *)
		     DhcpOptions.val[classlessStaticRoutes])[3 + i],
		    ((unsigned char *)
		     DhcpOptions.val[classlessStaticRoutes])[4 + i],
		    ((unsigned char *)
		     DhcpOptions.val[classlessStaticRoutes])[5 + i],
		    ((unsigned char *)
		     DhcpOptions.val[classlessStaticRoutes])[6 + i],
		    ((unsigned char *)
		     DhcpOptions.val[classlessStaticRoutes])[7 + i],
		    ((unsigned char *)
		     DhcpOptions.val[classlessStaticRoutes])[8 + i],
		    ((unsigned char *)
		     DhcpOptions.val[classlessStaticRoutes])[9 + i],
		    ((unsigned char *)
		     DhcpOptions.val[classlessStaticRoutes])[10 + i],
		    ((unsigned char *)
		     DhcpOptions.val[classlessStaticRoutes])[11 + i]);
	}
      
      if (DhcpOptions.len[routersOnSubnet] > 3)
	{
	  fprintf (f, "\nGATEWAY=%u.%u.%u.%u",
		  ((unsigned char *) DhcpOptions.val[routersOnSubnet])[0],
		  ((unsigned char *) DhcpOptions.val[routersOnSubnet])[1],
		  ((unsigned char *) DhcpOptions.val[routersOnSubnet])[2],
		  ((unsigned char *) DhcpOptions.val[routersOnSubnet])[3]);
	  for (i = 4; i < DhcpOptions.len[routersOnSubnet]; i += 4)
	    fprintf (f, ",%u.%u.%u.%u",
		    ((unsigned char *) DhcpOptions.val[routersOnSubnet])[i],
		    ((unsigned char *) DhcpOptions.val[routersOnSubnet])[1 + i],
		    ((unsigned char *) DhcpOptions.val[routersOnSubnet])[2 + i],
		    ((unsigned char *) DhcpOptions.val[routersOnSubnet])[3 + i]);
	}
      
      if (DhcpOptions.len[staticRoute])
	{
	  fprintf (f, "\nROUTE=%u.%u.%u.%u,%u.%u.%u.%u",
		  ((unsigned char *) DhcpOptions.val[staticRoute])[0],
		  ((unsigned char *) DhcpOptions.val[staticRoute])[1],
		  ((unsigned char *) DhcpOptions.val[staticRoute])[2],
		  ((unsigned char *) DhcpOptions.val[staticRoute])[3],
		  ((unsigned char *) DhcpOptions.val[staticRoute])[4],
		  ((unsigned char *) DhcpOptions.val[staticRoute])[5],
		  ((unsigned char *) DhcpOptions.val[staticRoute])[6],
		  ((unsigned char *) DhcpOptions.val[staticRoute])[7]);
	  for (i = 8;i < DhcpOptions.len[staticRoute]; i += 8)
	    fprintf (f, ",%u.%u.%u.%u,%u.%u.%u.%u",
		    ((unsigned char *) DhcpOptions.val[staticRoute])[i],
		    ((unsigned char *) DhcpOptions.val[staticRoute])[1+i],
		    ((unsigned char *) DhcpOptions.val[staticRoute])[2+i],
		    ((unsigned char *) DhcpOptions.val[staticRoute])[3+i],
		    ((unsigned char *) DhcpOptions.val[staticRoute])[4+i],
		    ((unsigned char *) DhcpOptions.val[staticRoute])[5+i],
		    ((unsigned char *) DhcpOptions.val[staticRoute])[6+i],
		    ((unsigned char *) DhcpOptions.val[staticRoute])[7+i]);
	}
      
      if (DhcpOptions.len[hostName])
	fprintf (f, "\nHOSTNAME=\'%s\'",cleanmetas ((char *)DhcpOptions.val[hostName]));
      
      if (DhcpOptions.len[domainName])
	fprintf (f, "\nDOMAIN=\'%s\'", cleanmetas ((char *) DhcpOptions.val[domainName]));
      
      if (DhcpOptions.len[nisDomainName])
	fprintf(f, "\nNISDOMAIN=\'%s\'", cleanmetas ((char *) DhcpOptions.val[nisDomainName]));
      
      if (DhcpOptions.len[rootPath])
	fprintf(f, "\nROOTPATH=\'%s\'", cleanmetas ((char *) DhcpOptions.val[rootPath]));
      
      fprintf (f, "\nDNS=%u.%u.%u.%u",
	      ((unsigned char *) DhcpOptions.val[dns])[0],
	      ((unsigned char *) DhcpOptions.val[dns])[1],
	      ((unsigned char *) DhcpOptions.val[dns])[2],
	      ((unsigned char *) DhcpOptions.val[dns])[3]);
      
      for (i = 4; i < DhcpOptions.len[dns]; i += 4)
	fprintf (f, ",%u.%u.%u.%u",
		((unsigned char *) DhcpOptions.val[dns])[i],
		((unsigned char *) DhcpOptions.val[dns])[1 + i],
		((unsigned char *) DhcpOptions.val[dns])[2 + i],
		((unsigned char *) DhcpOptions.val[dns])[3 + i]);
      
      if (DhcpOptions.len[dnsSearchPath])
	fprintf (f, "\nDNSSEARCH='%s'", cleanmetas ((char *)DhcpOptions.val[dnsSearchPath]));
      
      if (DhcpOptions.len[ntpServers] >= 4)
	{
	  fprintf (f, "\nNTPSERVERS=%u.%u.%u.%u",
		  ((unsigned char *) DhcpOptions.val[ntpServers])[0],
		  ((unsigned char *) DhcpOptions.val[ntpServers])[1],
		  ((unsigned char *) DhcpOptions.val[ntpServers])[2],
		  ((unsigned char *) DhcpOptions.val[ntpServers])[3]);
	  for (i = 4; i <DhcpOptions.len[ntpServers]; i += 4)
	    fprintf (f, ",%u.%u.%u.%u",
		    ((unsigned char *) DhcpOptions.val[ntpServers])[i],
		    ((unsigned char *) DhcpOptions.val[ntpServers])[1 + i],
		    ((unsigned char *) DhcpOptions.val[ntpServers])[2 + i],
		    ((unsigned char *) DhcpOptions.val[ntpServers])[3 + i]);
	}
      
      if (DhcpOptions.len[nisServers] >= 4)
	{
	  fprintf (f, "\nNISSERVERS=%u.%u.%u.%u",
		  ((unsigned char *) DhcpOptions.val[nisServers])[0],
		  ((unsigned char *) DhcpOptions.val[nisServers])[1],
		  ((unsigned char *) DhcpOptions.val[nisServers])[2],
		  ((unsigned char *) DhcpOptions.val[nisServers])[3]);
	  for (i = 4; i < DhcpOptions.len[nisServers]; i +=4)
	    fprintf (f, ",%u.%u.%u.%u",
		    ((unsigned char *) DhcpOptions.val[nisServers])[i],
		    ((unsigned char *) DhcpOptions.val[nisServers])[1 + i],
		    ((unsigned char *) DhcpOptions.val[nisServers])[2 + i],
		    ((unsigned char *) DhcpOptions.val[nisServers])[3 + i]);
	}
      
      fprintf(f,"\nDHCPSID=%u.%u.%u.%u\n"
	      "DHCPGIADDR=%u.%u.%u.%u\n"
	      "DHCPSIADDR=%u.%u.%u.%u\n"
	      "DHCPCHADDR=%02X:%02X:%02X:%02X:%02X:%02X\n"
	      "DHCPSHADDR=%02X:%02X:%02X:%02X:%02X:%02X\n"
	      "DHCPSNAME='%s'\n"
	      "LEASETIME=%u\n"
	      "RENEWALTIME=%u\n"
	      "REBINDTIME=%u\n"
	      "INTERFACE='%s'\n"
	      "CLASSID='%s'\n",
	      ((unsigned char *) DhcpOptions.val[dhcpServerIdentifier])[0],
	      ((unsigned char *) DhcpOptions.val[dhcpServerIdentifier])[1],
	      ((unsigned char *) DhcpOptions.val[dhcpServerIdentifier])[2],
	      ((unsigned char *) DhcpOptions.val[dhcpServerIdentifier])[3],
	      ((unsigned char *) &DhcpMsgRecv->giaddr)[0],
	      ((unsigned char *) &DhcpMsgRecv->giaddr)[1],
	      ((unsigned char *) &DhcpMsgRecv->giaddr)[2],
	      ((unsigned char *) &DhcpMsgRecv->giaddr)[3],
	      ((unsigned char *) &DhcpMsgRecv->siaddr)[0],
	      ((unsigned char *) &DhcpMsgRecv->siaddr)[1],
	      ((unsigned char *) &DhcpMsgRecv->siaddr)[2],
	      ((unsigned char *) &DhcpMsgRecv->siaddr)[3],
	      ClientHwAddr[0],
	      ClientHwAddr[1],
	      ClientHwAddr[2],
	      ClientHwAddr[3],
	      ClientHwAddr[4],
	      ClientHwAddr[5],
	      DhcpIface.shaddr[0],
	      DhcpIface.shaddr[1],
	      DhcpIface.shaddr[2],
	      DhcpIface.shaddr[3],
	      DhcpIface.shaddr[4],
	      DhcpIface.shaddr[5],
	      cleanmetas ((char *)DhcpMsgRecv->sname),
	      ntohl (*(unsigned int *) DhcpOptions.val[dhcpIPaddrLeaseTime]),
	      ntohl (*(unsigned int *) DhcpOptions.val[dhcpT1value]),
	      ntohl (*(unsigned int *) DhcpOptions.val[dhcpT2value]),
	      IfNameExt,
	      DhcpIface.class_id);
      
      if (ClientID)
	fprintf(f, "CLIENTID='%s'\n", ClientID);
      else
	fprintf(f, "CLIENTID=%02X:%02X:%02X:%02X:%02X:%02X\n",
		DhcpIface.client_id[3], DhcpIface.client_id[4],
		DhcpIface.client_id[5], DhcpIface.client_id[6],
		DhcpIface.client_id[7], DhcpIface.client_id[8]);
      
      if (SetFQDNHostName != FQDNdisable)
	{
	  if (DhcpOptions.len[dhcpFQDNHostName])
	    {
	      fprintf (f, "FQDNFLAGS=%u\n"
		      "FQDNRCODE1=%u\n"
		      "FQDNRCODE2=%u\n"
		      "FQDNHOSTNAME='%s'\n",
		      ((unsigned char *) DhcpOptions.val[dhcpFQDNHostName])[0],
		      ((unsigned char *) DhcpOptions.val[dhcpFQDNHostName])[1],
		      ((unsigned char *) DhcpOptions.val[dhcpFQDNHostName])[2],
		      (cleanmetas (((char *) DhcpOptions.val[dhcpFQDNHostName]) + 3)));
	    }
	}
      
      fclose (f);
      have_info = 1;
    }
  else
    logger (LOG_ERR, "dhcpConfig: fopen %s: %s", hostinfo_file,
	    strerror (errno));

  if (DhcpIface.ciaddr == prev_ip_addr)
    execute_on_change ("up");
  else					/* IP address has changed */
    {
      execute_on_change ("new");
      prev_ip_addr = DhcpIface.ciaddr;
    }

  return 0;
}

