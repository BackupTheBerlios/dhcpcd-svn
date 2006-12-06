/*
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 2005 - 2006 Roy Marples <uberlord@gentoo.org>
 *
 * dhcpcd is an RFC2131 compliant DHCP client daemon.
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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <arpa/inet.h>

#ifdef __linux__
#include <netinet/ether.h>
#endif
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"
#include "dhcp.h"
#include "interface.h"
#include "dhcpcd.h"
#include "pathnames.h"
#include "logger.h"
#include "socket.h"

static char *cleanmetas (char *cstr)
{
  if (! cstr)
    return "";
  
  register char *c = cstr;

  do
    if (*c == 39)
      *c = ' ';
  while (*c++);
  
  return cstr;
}

void exec_script (char *script, char *infofile, char *arg)
{
  if (! script || ! infofile || ! arg)
    return;

  struct stat buf;
  if (stat (script, &buf) < 0)
    {
      if (strcmp (script, DEFAULT_SCRIPT) != 0)
	logger (LOG_ERR, "`%s': %s", script, strerror (ENOENT));
      return;
    }
  
  char *argc[4];

  argc[0] = script;
  argc[1] = infofile;
  argc[2] = arg;
  argc[3] = NULL;
  logger (LOG_DEBUG, "exec \"%s %s %s\"", script, infofile, arg);
  
  /* We don't wait for the user script to finish - do we trust it? */
  /* Don't use vfork as we lose our memory when dhcpcd exits
     causing the script to fail */
  pid_t pid;
  if ((pid = fork ()) == 0)
    {
      if (execv (script, argc))
	logger (LOG_ERR, "error executing \"%s %s %s\": %s",
		argc[0], argc[1], argc[2], strerror (errno));
      exit (0);
    }
  else if (pid == -1)
    logger (LOG_ERR, "fork: %s", strerror (errno));
}

static int make_resolv (char *ifname, dhcp_t *dhcp)
{
  FILE *f;
  struct stat buf;
  char resolvconf[PATH_MAX] = {0};
  address_t *address;

  if (stat (RESOLVCONF, &buf) == 0)
    {
      logger (LOG_DEBUG, "sending DNS information to resolvconf");
      snprintf (resolvconf, PATH_MAX, RESOLVCONF" -a %s", ifname);
      f = popen (resolvconf, "w");

      if (! f)
	logger (LOG_ERR, "popen: %s", strerror (errno));
    }
  else
    {
      logger (LOG_DEBUG, "writing "RESOLVFILE);
      if (! (f = fopen(RESOLVFILE, "w")))
	logger (LOG_ERR, "fopen `%s': %s", RESOLVFILE, strerror (errno));
    }

  if (f) 
    {
      fprintf (f, "# Generated by dhcpcd for interface %s\n", ifname);
      if (dhcp->dnssearch)
	fprintf (f, "search %s\n", dhcp->dnssearch);
      else if (dhcp->dnsdomain) {
	fprintf (f, "search %s\n", dhcp->dnsdomain);
      }

      for (address = dhcp->dnsservers; address; address = address->next)
	fprintf (f, "nameserver %s\n", inet_ntoa (address->address));

      if (*resolvconf)
	pclose (f);
      else
	fclose (f);
    }
  else
    return -1;

  /* Refresh the local resolver */
  res_init ();
  return 0;
}

static void restore_resolv(char *ifname)
{
  struct stat buf;

  if (stat (RESOLVCONF, &buf) < 0)
    return;

  logger (LOG_DEBUG, "removing information from resolvconf");

  char *argc[4];

  argc[0] = RESOLVCONF;
  argc[1] = "-d";
  argc[2] = ifname;
  argc[3] = NULL;

  /* Don't wait around here as we should only be called when
     dhcpcd is closing down and something may do a kill -9
     if we take too long */
  /* Don't use vfork as we lose our memory when dhcpcd exits
     causing the script to fail */
  pid_t pid;
  if ((pid = fork ()) == 0)
    {
      if (execve (argc[0], argc, NULL))
	logger (LOG_ERR, "error executing \"%s %s %s\": %s",
		argc[0], argc[1], argc[2], strerror (errno));
      exit (0);
    }
  else if (pid == -1)
    logger (LOG_ERR, "fork: %s", strerror (errno));
}

static int make_ntp (char *ifname, dhcp_t *dhcp)
{
  FILE *f;
  address_t *address;
  char *a;

  logger (LOG_DEBUG, "writing "NTPFILE);
  if (! (f = fopen(NTPFILE, "w")))
    {
      logger (LOG_ERR, "fopen `%s': %s", NTPFILE, strerror (errno));
      return -1;
    }
	  
  fprintf (f, "# Generated by dhcpcd for interface %s\n", ifname);
  fprintf (f, "restrict default noquery notrust nomodify\n");
  fprintf (f, "restrict 127.0.0.1\n");

  for (address = dhcp->ntpservers; address; address = address->next)
    {
      a = inet_ntoa (address->address);
      fprintf (f, "restrict %s nomodify notrap noquery\nserver %s\n", a, a);
    }

  fprintf (f, "driftfile " NTPDRIFTFILE "\n");
  fprintf (f, "logfile " NTPLOGFILE "\n");
  fclose (f);
  return 0;
}

static int make_nis (char *ifname, dhcp_t *dhcp)
{
  FILE *f;
  address_t *address;
  char prefix[256] = {0};

  logger (LOG_DEBUG, "writing "NISFILE);
  if (! (f = fopen(NISFILE, "w")))
    {
      logger (LOG_ERR, "fopen `%s': %s", NISFILE, strerror (errno));
      return -1;
    }

  fprintf (f, "# Generated by dhcpcd for interface %s\n", ifname);
  if (dhcp->nisdomain)
    {
      setdomainname (dhcp->nisdomain, strlen (dhcp->nisdomain));

      if (dhcp->nisservers)
	snprintf (prefix, sizeof (prefix), "domain %s server", dhcp->nisdomain);
      else
	fprintf (f, "domain %s broadcast\n", dhcp->nisdomain);
    }
  else
    sprintf(prefix, "ypserver %c", '\0');

  for (address = dhcp->nisservers; address; address = address->next)
    fprintf (f, "%s%s\n", prefix, inet_ntoa (address->address));

  fclose (f);
  
  return 0;
}

static int write_info(interface_t *iface, dhcp_t *dhcp)
{
  FILE *f;
  route_t *route;
  address_t *address;

  logger (LOG_DEBUG, "writing %s", iface->infofile);
  if ((f = fopen (iface->infofile, "w")) == NULL)
    {
      logger (LOG_ERR, "fopen `%s': %s", iface->infofile, strerror (errno));
      return -1;
    }

  fprintf (f, "IPADDR='%s'\n", inet_ntoa (dhcp->address));
  fprintf (f, "NETMASK='%s'\n", inet_ntoa (dhcp->netmask));
  fprintf (f, "BROADCAST='%s'\n", inet_ntoa (dhcp->broadcast));
  if (dhcp->mtu > 0)
    fprintf (f, "MTU='%d'\n", dhcp->mtu);
  
  if (dhcp->routes)
    {
      fprintf (f, "ROUTES='");
      for (route = dhcp->routes; route; route = route->next)
	{
	  fprintf (f, "%s", inet_ntoa (route->destination));
	  fprintf (f, ",%s", inet_ntoa (route->netmask));
	  fprintf (f, ",%s", inet_ntoa (route->gateway));
	  if (route->next)
	    fprintf (f, " ");
	}
      fprintf (f, "'\n");
    }

  if (dhcp->hostname)
    fprintf (f, "HOSTNAME='%s'\n",cleanmetas (dhcp->hostname));

  if (dhcp->dnsdomain)
    fprintf (f, "DNSDOMAIN='%s'\n", cleanmetas (dhcp->dnsdomain));

  if (dhcp->dnssearch)
    fprintf (f, "DNSSEARCH='%s'\n", cleanmetas (dhcp->dnssearch));

  if (dhcp->dnsservers)
    {
      fprintf (f, "DNSSERVERS='");
      for (address = dhcp->dnsservers; address; address = address->next)
	{
	  fprintf (f, "%s", inet_ntoa (address->address));
	  if (address->next)
	    fprintf (f, " ");
	}
      fprintf (f, "'\n");
    }

  if (dhcp->fqdn)
    {
      fprintf (f, "FQDNFLAGS='%u'\n", dhcp->fqdn->flags);
      fprintf (f, "FQDNRCODE1='%u'\n", dhcp->fqdn->r1);
      fprintf (f, "FQDNRCODE2='%u'\n", dhcp->fqdn->r2);
      fprintf (f, "FQDNHOSTNAME='%s'\n", dhcp->fqdn->name);
    }

  if (dhcp->ntpservers)
    {
      fprintf (f, "NTPSERVERS='");
      for (address = dhcp->ntpservers; address; address = address->next)
	{
	  fprintf (f, "%s", inet_ntoa (address->address));
	  if (address->next)
	    fprintf (f, " ");
	}
      fprintf (f, "'\n");
    }

  if (dhcp->nisdomain)
    fprintf (f, "NISDOMAIN='%s'\n", cleanmetas (dhcp->nisdomain));

  if (dhcp->nisservers)
    {
      fprintf (f, "NISSERVERS='");
      for (address = dhcp->nisservers; address; address = address->next)
	{
	  fprintf (f, "%s", inet_ntoa (address->address));
	  if (address->next)
	    fprintf (f, " ");
	}
      fprintf (f, "'\n");
    }
 
  if (dhcp->rootpath)
    fprintf (f, "ROOTPATH='%s'\n", cleanmetas (dhcp->rootpath));

  fprintf (f, "DHCPSID='%s'\n", inet_ntoa (dhcp->serveraddress));
  fprintf (f, "DHCPCHADDR='%s'\n", ether_ntoa (&iface->ethernet_address));
  fprintf (f, "DHCPSNAME='%s'\n", cleanmetas (dhcp->servername));
  fprintf (f, "LEASETIME='%u'\n", dhcp->leasetime);
  fprintf (f, "RENEWALTIME='%u'\n", dhcp->renewaltime);
  fprintf (f, "REBINDTIME='%u'\n", dhcp->rebindtime);
  fprintf (f, "INTERFACE='%s'\n", iface->name);
  fprintf (f, "CLASSID='%s'\n", cleanmetas (dhcp->classid));
  fprintf (f, "CLIENTID='%s'\n", cleanmetas (dhcp->clientid));

  fclose (f);
  return 0;
}

int configure (options_t *options, interface_t *iface, dhcp_t *dhcp)
{
  route_t *route = NULL;
  route_t *new_route = NULL;
  route_t *old_route = NULL;
  struct hostent *he = NULL;
  char newhostname[HOSTNAME_MAX_LEN] = {0};
  char curhostname[HOSTNAME_MAX_LEN] = {0};
  char *dname = NULL;
  int dnamel = 0;
 
  if (! options || ! iface || ! dhcp)
    return -1;

  /* Remove old routes
     Always do this as the interface may have >1 address not added by us
     so the routes we added may still exist */
  if (iface->previous_routes)
    {
      for (route = iface->previous_routes; route; route = route->next)
	if (route->destination.s_addr || options->dogateway)
	  {
	    int have = 0;
	    if (dhcp->address.s_addr != 0)
	      for (new_route = dhcp->routes; new_route; new_route = new_route->next)
		if (new_route->destination.s_addr == route->destination.s_addr
		    && new_route->netmask.s_addr == route->netmask.s_addr
		    && new_route->gateway.s_addr == route->gateway.s_addr)
		   {
		     have = 1;
		     break;
		   }
	    if (! have)
	      del_route (iface->name, route->destination, route->netmask,
			 route->gateway, options->metric);
	  }
    }

  /* If we don't have an address, then return */
  if (dhcp->address.s_addr == 0)
    {
      if (iface->previous_routes)
	{
	  free_route (iface->previous_routes);
	  iface->previous_routes = NULL;
	}

      /* Only reset things if we had set them before */
      if (iface->previous_address.s_addr != 0)
	{
	  del_address (iface->name, iface->previous_address);
	  memset (&iface->previous_address, 0, sizeof (struct in_addr));

	  restore_resolv (iface->name);

	  /* we currently don't have a resolvconf style programs for ntp/nis */
	  exec_script (options->script, iface->infofile, "down");
	}
      return 0;
    }

  if (add_address (iface->name, dhcp->address, dhcp->netmask,
		   dhcp->broadcast) < 0 && errno != EEXIST)
    return -1;

  /* Now delete the old address if different */
  if (iface->previous_address.s_addr != dhcp->address.s_addr
      && iface->previous_address.s_addr != 0)
  	del_address (iface->name, iface->previous_address);

#ifdef __linux__
  /* On linux, we need to change the subnet route to have our metric. */
  if (iface->previous_address.s_addr != dhcp->address.s_addr
      && options->metric > 0)
    {
      struct in_addr td;
      struct in_addr tg;
      memset (&td, 0, sizeof (td));
      memset (&tg, 0, sizeof (tg));
      td.s_addr = dhcp->address.s_addr & dhcp->netmask.s_addr;
      add_route (iface->name, td, dhcp->netmask, tg, options->metric);
      del_route (iface->name, td, dhcp->netmask, tg, 0);
    }
#endif

  /* Remember added routes */
  if (dhcp->routes)
    {
      route_t *new_routes = NULL;
      
      for (route = dhcp->routes; route; route = route->next)
	{
	  /* Don't set default routes if not asked to */
	  if (route->destination.s_addr == 0 && route->netmask.s_addr == 0
	      && ! options->dogateway)
	    continue;

	  int remember = add_route (iface->name, route->destination,
				    route->netmask,  route->gateway,
				    options->metric);
	  /* If we failed to add the route, we may have already added it
	     ourselves. If so, remember it again. */
	  if (remember < 0)
	    for (old_route = iface->previous_routes; old_route;
		 old_route = old_route->next)
	      if (old_route->destination.s_addr == route->destination.s_addr
		  && old_route->netmask.s_addr == route->netmask.s_addr
		  && old_route->gateway.s_addr == route->gateway.s_addr)
		{
		  remember = 1;
		  break;
		}

	  if (remember >= 0)
	    {
	      if (! new_routes)
		{
		  new_routes = xmalloc (sizeof (route_t));
		  memset (new_routes, 0, sizeof (route_t));
		  new_route = new_routes;
		}
	      else
		{
		  new_route->next = xmalloc (sizeof (route_t));
		  new_route = new_route->next;
		}
	      memcpy (new_route, route, sizeof (route_t));
	      new_route -> next = NULL;
	    }
	}

      if (iface->previous_routes)
	free_route (iface->previous_routes);

      iface->previous_routes = new_routes;
    }

  if (options->dodns && dhcp->dnsservers)
    make_resolv(iface->name, dhcp);
  else
    logger (LOG_DEBUG, "no dns information to write");

  if (options->dontp && dhcp->ntpservers)
    make_ntp(iface->name, dhcp);

  if (options->donis && (dhcp->nisservers || dhcp->nisdomain))
    make_nis(iface->name, dhcp);

  /* Now we have made a resolv.conf we can obtain a hostname if we need one */
  if (options->dohostname && ! dhcp->hostname)
    {
      he = gethostbyaddr (inet_ntoa (dhcp->address),
			  sizeof (struct in_addr), AF_INET);
      if (he)
	{
	  dname = he->h_name;
	  while (*dname > 32)
	    dname++;
	  dnamel = dname - he->h_name;
	  memcpy (newhostname, he->h_name, dnamel);
	  newhostname[dnamel] = 0;
	}
    }

  gethostname (curhostname, sizeof (curhostname));
  
  if (options->dohostname
      || strlen (curhostname) == 0
      || strcmp (curhostname, "(none)") == 0
      || strcmp (curhostname, "localhost") == 0)
    {
      if (dhcp->hostname)
	strcpy (newhostname, dhcp->hostname); 

      if (*newhostname)
	{
	  logger (LOG_INFO, "setting hostname to `%s'", newhostname);
	  sethostname (newhostname, strlen (newhostname));
	}
    }

  write_info (iface, dhcp);

   if (iface->previous_address.s_addr != dhcp->address.s_addr)
    {
      memcpy (&iface->previous_address,
	      &dhcp->address, sizeof (struct in_addr));
      exec_script (options->script, iface->infofile, "new");
    }
  else
    exec_script (options->script, iface->infofile, "up");

  return 0;
}

