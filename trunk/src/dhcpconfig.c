/*
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 * Copyright (C) January, 1998 Sergei Viznyuk <sv@phystech.com>
 * Copyright (C) 2005 Roy Marples <uberlord@gentoo.org>
 * Copyright (C) 2005 Simon Kelley <simon@thekelleys.org.uk> 
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
#include <arpa/nameser.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <resolv.h>
#include <netdb.h>
#include "kversion.h"
#include "pathnames.h"
#include "client.h"
#include "logger.h"

extern 	int			DebugFlag;
extern	int			dhcpSocket;
extern  int                     udpFooSocket;
extern	int			prev_ip_addr;
extern	int			Window;
extern  int			SetDHCPDefaultRoutes;
extern	int			TestCase;
extern	int			SetDomainName;
extern	int			SetHostName;
extern	int			ReplResolvConf;
extern	int			ReplNISConf;
extern	int			ReplNTPConf;
extern  int			RouteMetric;
extern	int			IfName_len,IfNameExt_len;
extern	char			*IfName,*IfNameExt,*Cfilename,*ConfigDir;
extern	char			**ProgramEnviron;
extern	unsigned char		ClientHwAddr[ETH_ALEN],*ClientID;
extern	struct in_addr		default_router;
extern	dhcpInterface		DhcpIface;
extern	dhcpOptions		DhcpOptions;
extern	const dhcpMessage	*DhcpMsgRecv;

extern	char			resolv_file[128];
extern	char			resolv_file_sv[128];
extern	char			ntp_file[128];
extern	char			ntp_file_sv[128];
extern	char			nis_file[128];
extern	char			nis_file_sv[128];

extern	int			SetFQDNHostName;

int	arpInform();

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

/*****************************************************************************/
char *cleanmetas(cstr) /* this is to clean single quotes out of DHCP strings */
char *cstr;		/* replace single quotes with space */
{
  register char *c=cstr;
  do
    if ( *c == 39 ) *c = ' ';
  while ( *c++ );
  return cstr;
}

/*****************************************************************************/
void execute_on_change(prm)
char *prm;
{
  if (!have_info)
    return;
  
#ifdef EMBED
  if ( vfork() == 0 )
#else
  if ( fork() == 0 )
#endif
    {
      char *argc[3],exec_on_change[128];
      
      if ( Cfilename )
	snprintf(exec_on_change,sizeof(exec_on_change),Cfilename);
      else
	snprintf(exec_on_change,sizeof(exec_on_change),EXEC_ON_CHANGE);
      argc[0]=exec_on_change;
      argc[1]=hostinfo_file;
      argc[2]=prm;
      argc[3]=NULL;
      if ( execve(exec_on_change,argc,ProgramEnviron) && errno != ENOENT )
	logger(LOG_ERR,"error executing \"%s %s %s\": %s",
	exec_on_change,hostinfo_file,prm,strerror(errno));
      exit(0);
    }
}
/*****************************************************************************/
unsigned long getgenmask(ip_in)		/* this is to guess genmask	*/
unsigned long ip_in;			/* from network address		*/
{
  unsigned long t,p=ntohl(ip_in);
  if ( IN_CLASSA(p) )
    t= ~IN_CLASSA_NET;
  else
    {
      if ( IN_CLASSB(p) )
	t= ~IN_CLASSB_NET;
      else
	{
	  if ( IN_CLASSC(p) )
	    t= ~IN_CLASSC_NET;
	  else
	    t=0;
	}
    }
  while ( t&p ) t>>=1;
  return htonl(~t);
}
/*****************************************************************************/
int setDefaultRoute(route_addr)
char *route_addr;
{
struct	rtentry		rtent;
struct	sockaddr_in	*p;

memset(&rtent,0,sizeof(struct rtentry));
p			=	(struct sockaddr_in *)&rtent.rt_dst;
p->sin_family		=	AF_INET;
p->sin_addr.s_addr	=	0;
p			=	(struct sockaddr_in *)&rtent.rt_gateway;
p->sin_family		=	AF_INET;
memcpy(&p->sin_addr.s_addr,route_addr,4);
p			=	(struct sockaddr_in *)&rtent.rt_genmask;
p->sin_family		=	AF_INET;
p->sin_addr.s_addr	=	0;
#ifdef OLD_LINUX_VERSION
  rtent.rt_dev		=	IfName;
#else
  rtent.rt_dev		=	IfNameExt;
#endif
rtent.rt_metric	        =	RouteMetric;
rtent.rt_window		=	Window;
rtent.rt_flags	        =	RTF_UP|RTF_GATEWAY|(Window ? RTF_WINDOW : 0);
if ( ioctl(dhcpSocket,SIOCADDRT,&rtent) == -1 )
  {
    if ( errno == ENETUNREACH )    /* possibly gateway is over the bridge */
      {                            /* try adding a route to gateway first */
	memset(&rtent,0,sizeof(struct rtentry));
	p			=	(struct sockaddr_in *)&rtent.rt_dst;
	p->sin_family		=	AF_INET;
	memcpy(&p->sin_addr.s_addr,route_addr,4);
	p			=	(struct sockaddr_in *)&rtent.rt_gateway;
	p->sin_family		=	AF_INET;
	p->sin_addr.s_addr	=	0;
	p			=	(struct sockaddr_in *)&rtent.rt_genmask;
	p->sin_family		=	AF_INET;
	p->sin_addr.s_addr	=	0xffffffff;
#ifdef OLD_LINUX_VERSION
	rtent.rt_dev		=	IfName;
#else
	rtent.rt_dev		=	IfNameExt;
#endif
	rtent.rt_metric     =	  RouteMetric;
	rtent.rt_flags      =	  RTF_UP|RTF_HOST;
	if ( ioctl(dhcpSocket,SIOCADDRT,&rtent) == 0 )
	  {
	    memset(&rtent,0,sizeof(struct rtentry));
	    p			=	(struct sockaddr_in *)&rtent.rt_dst;
	    p->sin_family	=	AF_INET;
	    p->sin_addr.s_addr	=	0;
	    p			=	(struct sockaddr_in *)&rtent.rt_gateway;
	    p->sin_family	=	AF_INET;
	    memcpy(&p->sin_addr.s_addr,route_addr,4);
	    p			=	(struct sockaddr_in *)&rtent.rt_genmask;
	    p->sin_family	=	AF_INET;
	    p->sin_addr.s_addr	=	0;
#ifdef OLD_LINUX_VERSION
	    rtent.rt_dev	=	IfName;
#else
	    rtent.rt_dev	=	IfNameExt;
#endif
	    rtent.rt_metric	=	RouteMetric;
	    rtent.rt_window	=	Window;
	    rtent.rt_flags	=	RTF_UP|RTF_GATEWAY|(Window ? RTF_WINDOW : 0);
	    if ( ioctl(dhcpSocket,SIOCADDRT,&rtent) == -1 )
	      {
		logger(LOG_ERR,"dhcpConfig: ioctl SIOCADDRT: %s",strerror(errno));
		return -1;
	      }
	  }
      }
    else
      {
	logger(LOG_ERR,"dhcpConfig: ioctl SIOCADDRT: %s",strerror(errno));
	return -1;
      }
  }
return 0;
}

int islink(char *file) {
    char b[1];
    int n = readlink(file, b, 1);
    if (n == -1)
	return 0;
    else
	return 1;
}

/*****************************************************************************/
int dhcpConfig()
{
  int i;
  FILE *f = NULL;
  char hostinfo_file_old[128];
  struct ifreq		ifr;
  struct rtentry	rtent;
#ifdef OLD_LINUX_VERSION
  struct sockaddr_pkt	sap;
#endif
  struct sockaddr_in	*p = (struct sockaddr_in *)&(ifr.ifr_addr);
  struct hostent *hp=NULL;
  char *dname=NULL;
  int dname_len=0;

  if ( TestCase ) goto tsc;
  memset(&ifr,0,sizeof(struct ifreq));
#ifdef OLD_LINUX_VERSION
  memcpy(ifr.ifr_name,IfName,IfName_len);
#else
  memcpy(ifr.ifr_name,IfNameExt,IfNameExt_len);
#endif
  p->sin_family = AF_INET;
  p->sin_addr.s_addr = DhcpIface.ciaddr;
  if ( ioctl(dhcpSocket,SIOCSIFADDR,&ifr) == -1 )  /* setting IP address */
    {
      logger(LOG_ERR,"dhcpConfig: ioctl SIOCSIFADDR: %s",strerror(errno));
      return -1;
    }
  memcpy(&p->sin_addr.s_addr,DhcpOptions.val[subnetMask],4);
  if ( ioctl(dhcpSocket,SIOCSIFNETMASK,&ifr) == -1 )  /* setting netmask */
    {
      p->sin_addr.s_addr = 0xffffffff; /* try 255.255.255.255 */
      if ( ioctl(dhcpSocket,SIOCSIFNETMASK,&ifr) == -1 )
	{
	  logger(LOG_ERR,"dhcpConfig: ioctl SIOCSIFNETMASK: %s",strerror(errno));
	  return -1;
	}
    }
  memcpy(&p->sin_addr.s_addr,DhcpOptions.val[broadcastAddr],4);
  if ( ioctl(dhcpSocket,SIOCSIFBRDADDR,&ifr) == -1 ) /* setting broadcast address */
    logger(LOG_ERR,"dhcpConfig: ioctl SIOCSIFBRDADDR: %s",strerror(errno));

  /* 
   * setting local route
   * need to delete kernel added route on newer kernels
   */
#ifndef OLD_LINUX_VERSION
  memset(&rtent,0,sizeof(struct rtentry));
  p			=	(struct sockaddr_in *)&rtent.rt_dst;
  p->sin_family		=	AF_INET;
  memcpy(&p->sin_addr.s_addr,DhcpOptions.val[subnetMask],4);
  p->sin_addr.s_addr	&=	DhcpIface.ciaddr;
  p			=	(struct sockaddr_in *)&rtent.rt_gateway;
  p->sin_family		=	AF_INET;
  p->sin_addr.s_addr	=	0;
  p			=	(struct sockaddr_in *)&rtent.rt_genmask;
  p->sin_family		=	AF_INET;
  memcpy(&p->sin_addr.s_addr,DhcpOptions.val[subnetMask],4);
  rtent.rt_dev		=	IfName;
  rtent.rt_metric     	=	1;
  rtent.rt_flags      	=	RTF_UP;
  if ( ioctl(dhcpSocket,SIOCDELRT,&rtent) )
    logger(LOG_ERR,"dhcpConfig: ioctl SIOCDELRT: %s",strerror(errno));
#endif
  
  memset(&rtent,0,sizeof(struct rtentry));
  p			=	(struct sockaddr_in *)&rtent.rt_dst;
  p->sin_family		=	AF_INET;
  memcpy(&p->sin_addr.s_addr,DhcpOptions.val[subnetMask],4);
  p->sin_addr.s_addr	&=	DhcpIface.ciaddr;
  p			=	(struct sockaddr_in *)&rtent.rt_gateway;
  p->sin_family		=	AF_INET;
  p->sin_addr.s_addr	=	0;
  p			=	(struct sockaddr_in *)&rtent.rt_genmask;
  p->sin_family		=	AF_INET;
  memcpy(&p->sin_addr.s_addr,DhcpOptions.val[subnetMask],4);
  rtent.rt_dev		=	IfName;
  rtent.rt_metric     	=	RouteMetric;
  rtent.rt_flags      	=	RTF_UP;
  if ( ioctl(dhcpSocket,SIOCADDRT,&rtent) )
    logger(LOG_ERR,"dhcpConfig: ioctl SIOCADDRT: %s",strerror(errno));

  for (i=0;i<DhcpOptions.len[staticRoute];i+=8)
    {  /* setting static routes */
      struct sockaddr_in *dstp; 
      struct sockaddr_in *gwp; 
      struct sockaddr_in *mskp; 
      memset(&rtent,0,sizeof(struct rtentry));
      dstp		=	(struct sockaddr_in *)&rtent.rt_dst;
      dstp->sin_family	=	AF_INET;
      memcpy(&dstp->sin_addr.s_addr,((char *)DhcpOptions.val[staticRoute])+i,4);
      gwp		=	(struct sockaddr_in *)&rtent.rt_gateway;
      gwp->sin_family	=	AF_INET;
      memcpy(&gwp->sin_addr.s_addr,((char *)DhcpOptions.val[staticRoute])+i+4,4);
      mskp		=	(struct sockaddr_in *)&rtent.rt_genmask;
      mskp->sin_family	=	AF_INET;
      mskp->sin_addr.s_addr = getgenmask(dstp->sin_addr.s_addr);
      rtent.rt_flags	=	RTF_UP|RTF_GATEWAY;
      if ( mskp->sin_addr.s_addr == 0xffffffff ) rtent.rt_flags |= RTF_HOST;

#ifdef OLD_LINUX_VERSION
      rtent.rt_dev	      =	  IfName;
#else
      rtent.rt_dev	      =	  IfNameExt;
#endif
      rtent.rt_metric     =	  RouteMetric;
      if ( ioctl(dhcpSocket,SIOCADDRT,&rtent) )
	logger(LOG_ERR,"dhcpConfig: ioctl SIOCADDRT: %s",strerror(errno));
    }

  if ( SetDHCPDefaultRoutes )
    {
      if ( DhcpOptions.len[routersOnSubnet] > 3 )
	for (i=0;i<DhcpOptions.len[routersOnSubnet];i+=4)
	  setDefaultRoute(DhcpOptions.val[routersOnSubnet]);
    }
  else
    if ( default_router.s_addr > 0 ) setDefaultRoute((char *)&(default_router.s_addr));

  /* rebind dhcpSocket after changing ip address to avoid problems with 2.0 kernels */
#ifdef OLD_LINUX_VERSION
  memset(&sap,0,sizeof(sap));
  sap.spkt_family = AF_INET;
  sap.spkt_protocol = htons(ETH_P_ALL);
  memcpy(sap.spkt_device,IfName,IfName_len);
  if ( bind(dhcpSocket,(void*)&sap,sizeof(struct sockaddr)) == -1 )
    logger(LOG_ERR,"dhcpConfig: bind: %s",strerror(errno));
#endif  

  arpInform();
  logger(LOG_INFO,"your IP address = %u.%u.%u.%u",
    ((unsigned char *)&DhcpIface.ciaddr)[0],
    ((unsigned char *)&DhcpIface.ciaddr)[1],
    ((unsigned char *)&DhcpIface.ciaddr)[2],
    ((unsigned char *)&DhcpIface.ciaddr)[3]);
  if ( ReplResolvConf && (DhcpOptions.len[domainName] || DhcpOptions.len[dns]))
    {
      if ( ! islink(resolv_file))
	resolv_renamed=1+rename(resolv_file, resolv_file_sv);

      struct stat buf;
      int resolvconf = 0;
      if ( ! stat("/sbin/resolvconf", &buf) ) {
        resolvconf = 1;
	char *arg = malloc(strlen("/sbin/resolvconf -a ")+strlen(IfName)+1);
	snprintf(arg, strlen("/sbin/resolvconf -a ")+strlen(IfName)+1,
	    "/sbin/resolvconf -a %s",IfName);
	f=popen(arg,"w");
	free(arg);
        if ( !f )
            logger(LOG_ERR,"dhcpConfig: popen: %s", strerror(errno));
      } else {
        f=fopen(resolv_file, "w");
        if ( !f )
            logger(LOG_ERR,"dhcpConfig: fopen %s: %s", resolv_file, strerror(errno));
      }
      if ( f ) 
	{
	  int i;
	  fprintf(f, "# Generated by dhcpcd for interface %s\n", IfName);
	  if ( DhcpOptions.len[dnsSearchPath] )
	    fprintf(f,"search %s\n", (char *)DhcpOptions.val[dnsSearchPath]);
	  else if ( DhcpOptions.len[domainName] ) {
	    fprintf(f,"search %s\n",(char *)DhcpOptions.val[domainName]);
	  }
	  
	  for (i=0;i<DhcpOptions.len[dns];i+=4)
	    fprintf(f,"nameserver %u.%u.%u.%u\n",
	    ((unsigned char *)DhcpOptions.val[dns])[i],
	    ((unsigned char *)DhcpOptions.val[dns])[i+1],
	    ((unsigned char *)DhcpOptions.val[dns])[i+2],
	    ((unsigned char *)DhcpOptions.val[dns])[i+3]);
	
	  if (resolvconf)
	    pclose(f);
	  else
	    fclose(f);
	}

   /* moved the next section of code from before to after we've created
    * resolv.conf. See below for explanation. <poeml@suse.de>
    * res_init() is normally called from within the first function of the
    * resolver which is called. Here, we want resolv.conf to be
    * reread. Otherwise, we won't be able to find out about our hostname,
    * because the resolver won't notice the change in resolv.conf */
      (void)res_init();
    }
  if ( ReplNISConf && (DhcpOptions.len[nisDomainName] || DhcpOptions.len[nisServers]))
    {
      if ( ! islink(nis_file))
	yp_renamed=1+rename(nis_file, nis_file_sv);
      f=fopen(nis_file, "w");
      if ( f )
	{
	  int i;
	  char *prefix=NULL;
	  fprintf(f, "# Generated by dhcpcd for interface %s\n", IfName);
	  if ( DhcpOptions.len[nisDomainName] ) {
	      if ( DhcpOptions.len[nisServers] ) {
		prefix=(char *)malloc(DhcpOptions.len[nisDomainName] + 15);
		sprintf(prefix, "domain %s server", (char *)DhcpOptions.val[nisDomainName]);
	      }
	      else
		fprintf(f, "domain %s broadcast\n", (char *)DhcpOptions.val[nisDomainName]);
	  }
	  else
	      prefix=strdup("ypserver");

	  for (i=0;i<DhcpOptions.len[nisServers];i+=4)
	    fprintf(f, "%s %u.%u.%u.%u\n", prefix,
	    ((unsigned char *)DhcpOptions.val[nisServers])[i],
	    ((unsigned char *)DhcpOptions.val[nisServers])[i+1],
	    ((unsigned char *)DhcpOptions.val[nisServers])[i+2],
	    ((unsigned char *)DhcpOptions.val[nisServers])[i+3]);
	  
	  fclose(f);

	  if (prefix) free(prefix);
	}
      else
	logger(LOG_ERR,"dhcpConfig: fopen %s: %s", nis_file, strerror(errno));
    }
  if ( ReplNTPConf && DhcpOptions.len[ntpServers]>=4 )
    {
      if ( ! islink(ntp_file))
	ntp_renamed=1+rename(ntp_file, ntp_file_sv);
      f=fopen(ntp_file, "w");
      if ( f )
 	{
 	  int net, mask;
	  int i;
	  char addr[4*3+3*1+1];
	  fprintf(f, "# Generated by dhcpcd for interface %s\n", IfName);
 	  memcpy(&mask,DhcpOptions.val[subnetMask],4);
 	  net = DhcpIface.ciaddr & mask;

 	  /* Note: Revise drift/log file names and stratum for local clock */
 	  fprintf(f,"restrict default noquery notrust nomodify\n");
 	  fprintf(f,"restrict 127.0.0.1\n");
  
	  for (i=0;i<DhcpOptions.len[ntpServers];i+=4)
	  {
	    snprintf(addr,sizeof(addr),"%u.%u.%u.%u",
	    ((unsigned char *)DhcpOptions.val[ntpServers])[i],
	    ((unsigned char *)DhcpOptions.val[ntpServers])[i+1],
	    ((unsigned char *)DhcpOptions.val[ntpServers])[i+2],
	    ((unsigned char *)DhcpOptions.val[ntpServers])[i+3]);
	    fprintf(f,"restrict %s nomodify notrap noquery\nserver %s\n",addr,addr);
	  }
 	  
	  fprintf(f, "driftfile /etc/ntp.drift\n");
 	  fprintf(f, "logfile /var/log/ntp.log\n");
 	  fclose(f);
 	}
       else
 	logger(LOG_ERR,"dhcpConfig: fopen %s: %s", ntp_file, strerror(errno));
     }
  if ( ! DhcpOptions.len[hostName] )
    {
      hp=gethostbyaddr((char *)&DhcpIface.ciaddr,
      sizeof(DhcpIface.ciaddr),AF_INET);
      if ( hp )
        {
	  dname=hp->h_name;
	  while ( *dname > 32 )
	    dname++;
	  dname_len=dname-hp->h_name;
	  DhcpOptions.val[hostName]=(char *)malloc(dname_len+1);
	  DhcpOptions.len[hostName]=dname_len;
	  memcpy((char *)DhcpOptions.val[hostName],
	    hp->h_name,dname_len);
	  ((char *)DhcpOptions.val[hostName])[dname_len]=0;
	  DhcpOptions.num++;
	}
    }
  if ( InitialHostName_len<0)
    {
      gethostname(InitialHostName,sizeof(InitialHostName));
      InitialHostName_len=strlen(InitialHostName);
    }
  logger(LOG_DEBUG,"orig hostname = %s",InitialHostName);
  if ( SetHostName || InitialHostName_len == 0 || ! strcmp(InitialHostName, "(none)") )
    {
      if ( DhcpOptions.len[hostName] )
        {
	  SetHostName = 1;
          sethostname(DhcpOptions.val[hostName],DhcpOptions.len[hostName]);
	  logger(LOG_INFO,"your hostname = %s",
	      (char *)DhcpOptions.val[hostName]);
	}
    }
  if ( SetDomainName )
    {
      if ( InitialDomainName_len<0 && getdomainname(InitialDomainName,sizeof(InitialDomainName))==0 )
	{
	  InitialDomainName_len=strlen(InitialDomainName);
	  logger(LOG_INFO,"orig domainname = %s",InitialDomainName);
	}
#if 0
      if ( DhcpOptions.len[nisDomainName] )
        {
          setdomainname(DhcpOptions.val[nisDomainName],
		      DhcpOptions.len[nisDomainName]);
	  if ( DebugFlag )
	    fprintf(stdout,"your domainname = %s\n",
		(char *)DhcpOptions.val[nisDomainName]);
        }
      else
        {
#endif
	  if ( ! DhcpOptions.len[domainName] )
	    {
	      if ( ! hp )
		hp=gethostbyaddr((char *)&DhcpIface.ciaddr,
		sizeof(DhcpIface.ciaddr),AF_INET);
	      if ( hp )
		{
		  dname=hp->h_name;
		  while ( *dname > 32 )
		    if ( *dname == '.' )
		      {
			dname++;
		        break;
		      }
		    else
		      dname++;
		  dname_len=strlen(dname);
		  if ( dname_len )
		    {
		      DhcpOptions.val[domainName]=(char *)malloc(dname_len+1);
		      DhcpOptions.len[domainName]=dname_len;
		      memcpy((char *)DhcpOptions.val[domainName],
		      dname,dname_len);
		      ((char *)DhcpOptions.val[domainName])[dname_len]=0;
		      DhcpOptions.num++;
		    }
		}
	    }
          if ( DhcpOptions.len[domainName] )
            {
	      setdomainname(DhcpOptions.val[domainName],
		DhcpOptions.len[domainName]);
	      logger(LOG_DEBUG,"your domainname = %s\n",
		(char *)DhcpOptions.val[domainName]);
	    }
#if 0
	}
#endif
    }
tsc:
  memset(DhcpIface.version,0,sizeof(DhcpIface.version));
  strncpy(DhcpIface.version,VERSION,sizeof(DhcpIface.version));
  snprintf(hostinfo_file_old,sizeof(hostinfo_file_old),DHCP_CACHE_FILE,CONFIG_DIR,IfNameExt);
  i=open(hostinfo_file_old,O_WRONLY|O_CREAT|O_TRUNC,S_IRUSR+S_IWUSR);
  if ( i == -1 ||
      write(i,(char *)&DhcpIface,sizeof(dhcpInterface)) == -1 ||
      close(i) == -1 )
    logger(LOG_ERR,"dhcpConfig: open/write/close: %s",strerror(errno));
  snprintf(hostinfo_file,sizeof(hostinfo_file),DHCP_HOSTINFO,ConfigDir,IfNameExt);
  snprintf(hostinfo_file_old,sizeof(hostinfo_file_old),""DHCP_HOSTINFO".old",ConfigDir,IfNameExt);
  rename(hostinfo_file,hostinfo_file_old);
  f=fopen(hostinfo_file,"w");
  if ( f )
    {
      int b,c;
      memcpy(&b,DhcpOptions.val[subnetMask],4);
      c = DhcpIface.ciaddr & b;
      fprintf(f,"\
IPADDR=%u.%u.%u.%u\n\
NETMASK=%u.%u.%u.%u\n\
NETWORK=%u.%u.%u.%u\n\
BROADCAST=%u.%u.%u.%u\n",
((unsigned char *)&DhcpIface.ciaddr)[0],
((unsigned char *)&DhcpIface.ciaddr)[1],
((unsigned char *)&DhcpIface.ciaddr)[2],
((unsigned char *)&DhcpIface.ciaddr)[3],
((unsigned char *)DhcpOptions.val[subnetMask])[0],
((unsigned char *)DhcpOptions.val[subnetMask])[1],
((unsigned char *)DhcpOptions.val[subnetMask])[2],
((unsigned char *)DhcpOptions.val[subnetMask])[3],
((unsigned char *)&c)[0],
((unsigned char *)&c)[1],
((unsigned char *)&c)[2],
((unsigned char *)&c)[3],
((unsigned char *)DhcpOptions.val[broadcastAddr])[0],
((unsigned char *)DhcpOptions.val[broadcastAddr])[1],
((unsigned char *)DhcpOptions.val[broadcastAddr])[2],
((unsigned char *)DhcpOptions.val[broadcastAddr])[3]);
      if ( DhcpOptions.len[routersOnSubnet] > 3 )
	{
	  fprintf(f,"\
GATEWAY=%u.%u.%u.%u",
((unsigned char *)DhcpOptions.val[routersOnSubnet])[0],
((unsigned char *)DhcpOptions.val[routersOnSubnet])[1],
((unsigned char *)DhcpOptions.val[routersOnSubnet])[2],
((unsigned char *)DhcpOptions.val[routersOnSubnet])[3]);
	  for (i=4;i<DhcpOptions.len[routersOnSubnet];i+=4)
  	    fprintf(f,",%u.%u.%u.%u",
	    ((unsigned char *)DhcpOptions.val[routersOnSubnet])[i],
	    ((unsigned char *)DhcpOptions.val[routersOnSubnet])[1+i],
	    ((unsigned char *)DhcpOptions.val[routersOnSubnet])[2+i],
	    ((unsigned char *)DhcpOptions.val[routersOnSubnet])[3+i]);
	}
if ( DhcpOptions.len[staticRoute] )
  {
    fprintf(f,"\nROUTE=%u.%u.%u.%u,%u.%u.%u.%u",
    ((unsigned char *)DhcpOptions.val[staticRoute])[0],
    ((unsigned char *)DhcpOptions.val[staticRoute])[1],
    ((unsigned char *)DhcpOptions.val[staticRoute])[2],
    ((unsigned char *)DhcpOptions.val[staticRoute])[3],
    ((unsigned char *)DhcpOptions.val[staticRoute])[4],
    ((unsigned char *)DhcpOptions.val[staticRoute])[5],
    ((unsigned char *)DhcpOptions.val[staticRoute])[6],
    ((unsigned char *)DhcpOptions.val[staticRoute])[7]);
    for (i=8;i<DhcpOptions.len[staticRoute];i+=8)
    fprintf(f,",%u.%u.%u.%u,%u.%u.%u.%u",
    ((unsigned char *)DhcpOptions.val[staticRoute])[i],
    ((unsigned char *)DhcpOptions.val[staticRoute])[1+i],
    ((unsigned char *)DhcpOptions.val[staticRoute])[2+i],
    ((unsigned char *)DhcpOptions.val[staticRoute])[3+i],
    ((unsigned char *)DhcpOptions.val[staticRoute])[4+i],
    ((unsigned char *)DhcpOptions.val[staticRoute])[5+i],
    ((unsigned char *)DhcpOptions.val[staticRoute])[6+i],
    ((unsigned char *)DhcpOptions.val[staticRoute])[7+i]);
  }
if ( DhcpOptions.len[hostName] )
  fprintf(f,"\nHOSTNAME=\'%s\'",cleanmetas((char *)DhcpOptions.val[hostName]));
if ( DhcpOptions.len[domainName] )
  fprintf(f,"\nDOMAIN=\'%s\'",cleanmetas((char *)DhcpOptions.val[domainName]));
if ( DhcpOptions.len[nisDomainName] )
  fprintf(f,"\nNISDOMAIN=\'%s\'",cleanmetas((char *)DhcpOptions.val[nisDomainName]));
if ( DhcpOptions.len[rootPath] )
  fprintf(f,"\nROOTPATH=\'%s\'",cleanmetas((char *)DhcpOptions.val[rootPath]));
fprintf(f,"\n\
DNS=%u.%u.%u.%u",
((unsigned char *)DhcpOptions.val[dns])[0],
((unsigned char *)DhcpOptions.val[dns])[1],
((unsigned char *)DhcpOptions.val[dns])[2],
((unsigned char *)DhcpOptions.val[dns])[3]);
for (i=4;i<DhcpOptions.len[dns];i+=4)
  fprintf(f,",%u.%u.%u.%u",
  ((unsigned char *)DhcpOptions.val[dns])[i],
  ((unsigned char *)DhcpOptions.val[dns])[1+i],
  ((unsigned char *)DhcpOptions.val[dns])[2+i],
  ((unsigned char *)DhcpOptions.val[dns])[3+i]);
if ( DhcpOptions.len[dnsSearchPath] )
  fprintf(f, "\nDNSSEARCH=\'%s\'", cleanmetas((char *)DhcpOptions.val[dnsSearchPath]));
if ( DhcpOptions.len[ntpServers]>=4 )
  {
    fprintf(f,"\nNTPSERVERS=%u.%u.%u.%u",
    ((unsigned char *)DhcpOptions.val[ntpServers])[0],
    ((unsigned char *)DhcpOptions.val[ntpServers])[1],
    ((unsigned char *)DhcpOptions.val[ntpServers])[2],
    ((unsigned char *)DhcpOptions.val[ntpServers])[3]);
    for (i=4;i<DhcpOptions.len[ntpServers];i+=4)
      fprintf(f,",%u.%u.%u.%u",
      ((unsigned char *)DhcpOptions.val[ntpServers])[i],
      ((unsigned char *)DhcpOptions.val[ntpServers])[1+i],
      ((unsigned char *)DhcpOptions.val[ntpServers])[2+i],
      ((unsigned char *)DhcpOptions.val[ntpServers])[3+i]);
  }
if ( DhcpOptions.len[nisServers]>=4 )
  {
    fprintf(f,"\nNISSERVERS=%u.%u.%u.%u",
    ((unsigned char *)DhcpOptions.val[nisServers])[0],
    ((unsigned char *)DhcpOptions.val[nisServers])[1],
    ((unsigned char *)DhcpOptions.val[nisServers])[2],
    ((unsigned char *)DhcpOptions.val[nisServers])[3]);
    for (i=4;i<DhcpOptions.len[nisServers];i+=4)
      fprintf(f,",%u.%u.%u.%u",
      ((unsigned char *)DhcpOptions.val[nisServers])[i],
      ((unsigned char *)DhcpOptions.val[nisServers])[1+i],
      ((unsigned char *)DhcpOptions.val[nisServers])[2+i],
      ((unsigned char *)DhcpOptions.val[nisServers])[3+i]);
  }
fprintf(f,"\n\
DHCPSID=%u.%u.%u.%u\n\
DHCPGIADDR=%u.%u.%u.%u\n\
DHCPSIADDR=%u.%u.%u.%u\n\
DHCPCHADDR=%02X:%02X:%02X:%02X:%02X:%02X\n\
DHCPSHADDR=%02X:%02X:%02X:%02X:%02X:%02X\n\
DHCPSNAME=\'%s\'\n\
LEASETIME=%u\n\
RENEWALTIME=%u\n\
REBINDTIME=%u\n\
INTERFACE=\'%s\'\n\
CLASSID=\'%s\'\n",
((unsigned char *)DhcpOptions.val[dhcpServerIdentifier])[0],
((unsigned char *)DhcpOptions.val[dhcpServerIdentifier])[1],
((unsigned char *)DhcpOptions.val[dhcpServerIdentifier])[2],
((unsigned char *)DhcpOptions.val[dhcpServerIdentifier])[3],
((unsigned char *)&DhcpMsgRecv->giaddr)[0],
((unsigned char *)&DhcpMsgRecv->giaddr)[1],
((unsigned char *)&DhcpMsgRecv->giaddr)[2],
((unsigned char *)&DhcpMsgRecv->giaddr)[3],
((unsigned char *)&DhcpMsgRecv->siaddr)[0],
((unsigned char *)&DhcpMsgRecv->siaddr)[1],
((unsigned char *)&DhcpMsgRecv->siaddr)[2],
((unsigned char *)&DhcpMsgRecv->siaddr)[3],
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
cleanmetas(DhcpMsgRecv->sname),
ntohl(*(unsigned int *)DhcpOptions.val[dhcpIPaddrLeaseTime]),
ntohl(*(unsigned int *)DhcpOptions.val[dhcpT1value]),
ntohl(*(unsigned int *)DhcpOptions.val[dhcpT2value]),
IfNameExt,
DhcpIface.class_id);
      if ( ClientID )
	fprintf(f,"CLIENTID=\'%s\'\n",ClientID);
      else
	fprintf(f,"CLIENTID=%02X:%02X:%02X:%02X:%02X:%02X\n",
DhcpIface.client_id[3],DhcpIface.client_id[4],DhcpIface.client_id[5],
DhcpIface.client_id[6],DhcpIface.client_id[7],DhcpIface.client_id[8]);
      if ( SetFQDNHostName != FQDNdisable )
        {
	  if ( DhcpOptions.len[dhcpFQDNHostName] )
	    {
fprintf(f,"FQDNFLAGS=%u\n\
FQDNRCODE1=%u\n\
FQDNRCODE2=%u\n\
FQDNHOSTNAME='%s'\n",
((unsigned char *)DhcpOptions.val[dhcpFQDNHostName])[0],
((unsigned char *)DhcpOptions.val[dhcpFQDNHostName])[1],
((unsigned char *)DhcpOptions.val[dhcpFQDNHostName])[2],
(cleanmetas(((char *)DhcpOptions.val[dhcpFQDNHostName])+3)));
	    }
	}
      fclose(f);
      have_info = 1;
    }
  else
    logger(LOG_ERR,"dhcpConfig: fopen %s: %s", hostinfo_file, strerror(errno));
#if 0
  if ( Cfilename )
    if ( fork() == 0 )
      {
	char *argc[2];
	argc[0]=Cfilename;
	argc[1]=NULL;
	if ( execve(Cfilename,argc,ProgramEnviron) )
	  logger(LOG_ERR,"error executing \"%s\": %s",
	  Cfilename,strerror(errno));
	exit(0);
      }
#endif
  if ( DhcpIface.ciaddr == prev_ip_addr )
    execute_on_change("up");
  else					/* IP address has changed */
    {
      execute_on_change("new");
      prev_ip_addr=DhcpIface.ciaddr;
    }
  if ( *(unsigned int *)DhcpOptions.val[dhcpIPaddrLeaseTime] == 0xffffffff )
    {
      logger(LOG_INFO,"infinite IP address lease time. Exiting");
      exit(0);
    }
  return 0;
}
/*****************************************************************************/
