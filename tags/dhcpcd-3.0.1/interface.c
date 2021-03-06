/*
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 2006 Roy Marples <uberlord@gentoo.org>
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>

/* Netlink suff */
#ifdef __linux__ 
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#else
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#endif /* __linux__ */

#include <errno.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "interface.h"
#include "logger.h"
#include "pathnames.h"

void free_address (address_t *addresses)
{
  if (!addresses)
    return;

  address_t *p = addresses;
  address_t *n = NULL;

  while (p)
    {
      n = p->next;
      free (p);
      p = n;
    }
}

void free_route (route_t *routes)
{
  if (!routes)
    return;

  route_t *p = routes;
  route_t *n = NULL;

  while (p)
    {
      n = p->next;
      free (p);
      p = n;
    }
}

interface_t *read_interface (const char *ifname, int metric)
{
  if (! ifname)
    return NULL;

  int s;
  struct ifreq ifr;
  interface_t *iface;
  unsigned char hwaddr[ETHER_ADDR_LEN];

  struct ifaddrs *ifap;
  struct ifaddrs *p;

  if (getifaddrs (&ifap) != 0)
    return NULL;

  for (p = ifap; p; p = p->ifa_next)
    {
      if (strcmp (p->ifa_name, ifname) != 0)
	continue;
#ifdef __linux__
      struct sockaddr_ll *sll = (struct sockaddr_ll*) p->ifa_addr;
      if (p->ifa_addr->sa_family != AF_PACKET
	  || sll->sll_hatype != ARPHRD_ETHER)
#else
	struct sockaddr_dl *sdl = (struct sockaddr_dl *) p->ifa_addr;
      if (p->ifa_addr->sa_family != AF_LINK || sdl->sdl_type != IFT_ETHER)
#endif
	{
	  logger (LOG_ERR, "not Ethernet");
	  freeifaddrs (ifap);
	  return NULL;
	}

#ifdef __linux__
      memcpy (hwaddr, sll->sll_addr, ETHER_ADDR_LEN);
#else
      memcpy (hwaddr, sdl->sdl_data + sdl->sdl_nlen, ETHER_ADDR_LEN);
#endif
      break;
    }
  freeifaddrs (ifap);

  if (!p)
    {
      logger (LOG_ERR, "could not find interface %s", ifname);
      return NULL;
    }

  memset (&ifr, 0, sizeof (struct ifreq));
  strncpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
      logger (LOG_ERR, "socket: %s", strerror (errno));
      return NULL;
    }

#ifndef __linux__
  ifr.ifr_metric = metric;
  if (ioctl(s, SIOCSIFMETRIC, &ifr) < 0)
    {
      logger (LOG_ERR, "ioctl SIOCSIFMETRIC: %s", strerror (errno));
      close (s);
      return NULL;
    }
#endif

  if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
    {
      logger (LOG_ERR, "ioctl SIOCGIFFLAGS: %s", strerror (errno));
      close (s);
      return NULL;
    }

  /* Bring the interface up if we need to */
  if (! (ifr.ifr_flags & IFF_UP))
    {
      ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
      if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
	{
	  logger (LOG_ERR, "ioctl SIOCSIFFLAGS: %s", strerror (errno));
	  close (s);
	  return NULL;
	}
    }

  close (s);

  iface = xmalloc (sizeof (interface_t));
  memset (iface, 0, sizeof (interface_t));
  strncpy (iface->name, ifname, IF_NAMESIZE);
  snprintf (iface->infofile, PATH_MAX, INFOFILE, ifname);
  memcpy (&iface->ethernet_address, &hwaddr, ETHER_ADDR_LEN);

  iface->arpable = ! (ifr.ifr_flags & (IFF_NOARP | IFF_LOOPBACK));

  logger (LOG_INFO, "ethernet address = %s",
	  ether_ntoa (&iface->ethernet_address));

  /* 0 is a valid fd, so init to -1 */
  iface->fd = -1;

  return iface;
}

#ifdef __FreeBSD__
static int do_address (const char *ifname, struct in_addr address,
		       struct in_addr netmask, struct in_addr broadcast, int del)
{
  if (! ifname)
    return -1;

  int s;
  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
    {
      logger (LOG_ERR, "socket: %s", strerror (errno));
      return -1;
    }

  struct ifaliasreq ifa;
  memset (&ifa, 0, sizeof (ifa));
  strcpy (ifa.ifra_name, ifname);

#define ADDADDR(_var, _addr) \
    { \
      struct sockaddr_in *_sin = (struct sockaddr_in *) &_var; \
      _sin->sin_family = AF_INET; \
      _sin->sin_len = sizeof (struct sockaddr_in); \
      memcpy (&_sin->sin_addr, &_addr, sizeof (struct in_addr)); \
    }

  ADDADDR (ifa.ifra_addr, address);
  if (! del)
    {
      ADDADDR (ifa.ifra_mask, netmask);
      ADDADDR (ifa.ifra_broadaddr, broadcast);
    }

#undef ADDADDR

  if (ioctl (s, del ? SIOCDIFADDR : SIOCAIFADDR, &ifa) == -1)
    {
      logger (LOG_ERR, "ioctl %s: %s", del ? "SIOCDIFADDR" : "SIOCAIFADDR",
	      strerror (errno));
      close (s);
      return -1;
    }

  close (s);
  return 0;
}

static int do_route (const char *ifname,
		     struct in_addr destination,
		     struct in_addr netmask,
		     struct in_addr gateway,
		     int metric,
		     int change, int del)
{
  if (! ifname)
    return -1;

  char *destd = strdup (inet_ntoa (destination));
  char *gend = strdup (inet_ntoa (netmask));
  logger (LOG_INFO, "%s route to %s (%s) via %s",
	  change ? "changing" : del ? "removing" : "adding",
	  destd, gend, inet_ntoa(gateway));
  if (destd)
    free (destd);
  if (gend)
    free (gend);

  int s;
  if ((s = socket(PF_ROUTE, SOCK_RAW, 0)) < 0) 
    {
      logger (LOG_ERR, "socket: %s", strerror (errno));
      return -1;
    }

  struct rtm
    {
      struct rt_msghdr hdr;
      struct sockaddr_in destination;
      struct sockaddr_in gateway;
      struct sockaddr_in netmask;
    } rtm;
  memset (&rtm, 0, sizeof (struct rtm));

  rtm.hdr.rtm_version = RTM_VERSION;
  static int seq;
  rtm.hdr.rtm_seq = ++seq;
  rtm.hdr.rtm_type = change ? RTM_CHANGE : del ? RTM_DELETE : RTM_ADD;

  rtm.hdr.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;
  if (netmask.s_addr == 0xffffffff)
    rtm.hdr.rtm_flags |= RTF_HOST;

  rtm.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;

#define ADDADDR(_var, _addr) \
  _var.sin_family = AF_INET; \
  _var.sin_len = sizeof (struct sockaddr_in); \
  memcpy (&_var.sin_addr, &_addr, sizeof (struct in_addr));

  ADDADDR (rtm.destination, destination);
  ADDADDR (rtm.gateway, gateway);
  ADDADDR (rtm.netmask, netmask);

#undef ADDADDR

  rtm.hdr.rtm_msglen = sizeof (rtm);

  if (write(s, &rtm, sizeof (rtm)) < 0)
    {
      /* Don't report error about routes already existing */
      if (errno != EEXIST)
	logger (LOG_ERR, "write: %s", strerror (errno));
      close (s);
      return -1;
    }

  close (s);
  return 0;
}

#elif __linux__
/* This netlink stuff is overly compex IMO.
   The BSD implementation is much cleaner and a lot less code.
   send_netlink handles the actual transmission so we can work out
   if there was an error or not.

   As always throughout this code, credit is due :)
   This blatently taken from libnetlink.c from the iproute2 package
   which is the only good source of netlink code.
   */
static int send_netlink(struct nlmsghdr *hdr)
{
  int s;
  if ((s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) 
    {
      logger (LOG_ERR, "socket: %s", strerror (errno));
      return -1;
    }

  int mypid = getpid ();
  struct sockaddr_nl nl;
  memset (&nl, 0, sizeof (struct sockaddr_nl));
  nl.nl_family = AF_NETLINK;
  if (bind (s, (struct sockaddr *) &nl, sizeof (nl)) < 0)
    {
      logger (LOG_ERR, "bind: %s", strerror (errno));
      close (s);
      return -1;
    }

  struct iovec iov;
  memset (&iov, 0, sizeof (struct iovec));
  iov.iov_base = hdr;
  iov.iov_len = hdr->nlmsg_len;

  struct msghdr msg;
  memset (&msg, 0, sizeof (struct msghdr));
  msg.msg_name = &nl;
  msg.msg_namelen = sizeof (nl);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  /* Request a reply */
  hdr->nlmsg_flags |= NLM_F_ACK;
  static int seq;
  hdr->nlmsg_seq = ++seq;

  if (sendmsg (s, &msg, 0) < 0)
    {
      logger (LOG_ERR, "write: %s", strerror (errno));
      close (s);
      return -1;
    }

  char buffer[16384];
  memset (&buffer, 0, sizeof (buffer));
  iov.iov_base = buffer;

  struct nlmsghdr *h;
  while (1) 
    {
      iov.iov_len = sizeof (buffer);
      int bytes = recvmsg(s, &msg, 0);

      if (bytes < 0)
	{
	  if (errno != EINTR)
	    logger (LOG_ERR, "overrun");
	  continue;
	}

      if (bytes == 0)
	{
	  logger (LOG_ERR, "EOF on netlink");
	  goto eexit;
	}

      if (msg.msg_namelen != sizeof (nl))
	{
	  logger (LOG_ERR, "sender address length == %d", msg.msg_namelen);
	  goto eexit;
	}

      for (h = (struct nlmsghdr *) buffer; bytes >= sizeof (*h); )
	{
	  int len = h->nlmsg_len;
	  int l = len - sizeof (*h);

	  if (l < 0 || len > bytes)
	    {
	      if (msg.msg_flags & MSG_TRUNC)
		logger (LOG_ERR, "truncated message");
	      else
		logger (LOG_ERR, "malformed message");
	      goto eexit;
	    }

	  if (nl.nl_pid != 0 ||
	      h->nlmsg_pid != mypid ||
	      h->nlmsg_seq != seq)
	    /* Message isn't for us, so skip it */
	    goto next;

	  /* We get an NLMSG_ERROR back with a code of zero for success */
	  if (h->nlmsg_type == NLMSG_ERROR)
	    {
	      struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA (h);
	      if (l < sizeof (struct nlmsgerr))
		logger (LOG_ERR, "truncated error message");
	      else
		{
		  errno = -err->error;
		  if (errno == 0)
		    {
		      close (s);
		      return 0;
		    }

		  /* Don't report on something already existing */
		  if (errno != EEXIST)
		    logger (LOG_ERR, "RTNETLINK answers: %s", strerror (errno));
		}
	      goto eexit;
	    }

	  logger (LOG_ERR, "unexpected reply");
next:
	  bytes -= NLMSG_ALIGN (len);
	  h = (struct nlmsghdr *) ((char *) h + NLMSG_ALIGN (len));
	}

      if (msg.msg_flags & MSG_TRUNC)
	{
	  logger (LOG_ERR, "message truncated");
	  continue;
	}

      if (bytes)
	{
	  logger (LOG_ERR, "remnant of size %d", bytes);
	  goto eexit;
	}
    }

eexit:
  close (s);
  return -1;
}

#define NLMSG_TAIL(nmsg) \
 ((struct rtattr *) (((unsigned char *) (nmsg)) \
		     + NLMSG_ALIGN((nmsg)->nlmsg_len)))
static int add_attr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
		      int alen)
{
  int len = RTA_LENGTH(alen);
  struct rtattr *rta;

  if (NLMSG_ALIGN (n->nlmsg_len) + RTA_ALIGN (len) > maxlen)
    {
      logger (LOG_ERR, "add_attr_l: message exceeded bound of %d\n", maxlen);
      return -1;
    }

  rta = NLMSG_TAIL (n);
  rta->rta_type = type;
  rta->rta_len = len;
  memcpy (RTA_DATA (rta), data, alen);
  n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + RTA_ALIGN (len);

  return 0;
}

static int add_attr_32(struct nlmsghdr *n, int maxlen, int type, uint32_t data)
{
  int len = RTA_LENGTH (sizeof (uint32_t));
  struct rtattr *rta;
  if (NLMSG_ALIGN (n->nlmsg_len) + len > maxlen)
    {
      logger (LOG_ERR, "add_attr32: message exceeded bound of %d\n", maxlen);
      return -1;
    }

  rta = NLMSG_TAIL (n);
  rta->rta_type = type;
  rta->rta_len = len;
  memcpy (RTA_DATA (rta), &data, sizeof (uint32_t));
  n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + len;

  return 0;
}


static int do_address(const char *ifname,
		      struct in_addr address, struct in_addr netmask,
		      struct in_addr broadcast, int del)
{
  if (!ifname)
    return -1;

  struct
    {
      struct nlmsghdr hdr;
      struct ifaddrmsg ifa;
      char buffer[256];
    }
  nlm;

  memset (&nlm, 0, sizeof (nlm));

  nlm.hdr.nlmsg_len = NLMSG_LENGTH (sizeof (struct ifaddrmsg));
  nlm.hdr.nlmsg_flags = NLM_F_REQUEST;
  nlm.hdr.nlmsg_type = del ? RTM_DELADDR : RTM_NEWADDR;
  nlm.ifa.ifa_index = if_nametoindex (ifname);
  nlm.ifa.ifa_family = AF_INET;

  /* Store the netmask in the prefix */
  uint32_t mask = htonl (netmask.s_addr);
  while (mask)
    {
      nlm.ifa.ifa_prefixlen++;
      mask <<= 1;
    }

  add_attr_l (&nlm.hdr, sizeof (nlm), IFA_LOCAL, &address.s_addr,
	      sizeof (address.s_addr));
  if (! del)
    add_attr_l (&nlm.hdr, sizeof (nlm), IFA_BROADCAST, &broadcast.s_addr,
		sizeof (broadcast.s_addr));

  return send_netlink (&nlm.hdr);
}

static int do_route (const char *ifname,
		     struct in_addr destination,
		     struct in_addr netmask,
		     struct in_addr gateway,
		     int metric, int change, int del)
{
  if (! ifname)
    return -1;

  char *dstd = strdup (inet_ntoa (destination));
  char *gend = strdup (inet_ntoa (netmask));
  logger (LOG_INFO, "%s route to %s (%s) via %s, metric %d",
	  change ? "changing" : del ? "removing" : "adding",
	  dstd, gend, inet_ntoa (gateway), metric);
  if (dstd)
    free (dstd);
  if (gend)
    free (gend);

  struct
    {
      struct nlmsghdr hdr;
      struct rtmsg rt;
      char buffer[256];
    }
  nlm;
  memset (&nlm, 0, sizeof (nlm));

  nlm.hdr.nlmsg_len = NLMSG_LENGTH (sizeof (struct rtmsg));
  if (change)
    nlm.hdr.nlmsg_flags = NLM_F_REPLACE;
  else if (! del)
    nlm.hdr.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL;
  nlm.hdr.nlmsg_flags |= NLM_F_REQUEST;
  nlm.hdr.nlmsg_type = del ? RTM_DELROUTE : RTM_NEWROUTE;
  nlm.rt.rtm_family = AF_INET;
  nlm.rt.rtm_table = RT_TABLE_MAIN;

  if (del)
    nlm.rt.rtm_scope = RT_SCOPE_NOWHERE;
  else
    {
      nlm.hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
      nlm.rt.rtm_protocol = RTPROT_BOOT;
      if (gateway.s_addr == 0)
	nlm.rt.rtm_scope = RT_SCOPE_LINK;
      else
	nlm.rt.rtm_scope = RT_SCOPE_UNIVERSE;
      nlm.rt.rtm_type = RTN_UNICAST;
    }

  /* Store the netmask in the prefix */
  uint32_t mask = htonl (netmask.s_addr);
  while (mask)
    {
      nlm.rt.rtm_dst_len++;
      mask <<= 1;
    }

  add_attr_l (&nlm.hdr, sizeof (nlm), RTA_DST, &destination.s_addr,
	      sizeof (destination.s_addr));
  if (gateway.s_addr != 0)
    add_attr_l (&nlm.hdr, sizeof (nlm), RTA_GATEWAY, &gateway.s_addr,
		sizeof (gateway.s_addr));

  add_attr_32 (&nlm.hdr, sizeof (nlm), RTA_OIF, if_nametoindex (ifname));
  add_attr_32 (&nlm.hdr, sizeof (nlm), RTA_PRIORITY, metric);

  return send_netlink (&nlm.hdr);
}

#else
#error "Platform not supported!"
#error "We currently support BPF and Linux sockets."
#error "Other platforms may work using BPF. If yours does, please let me know"
#error "so I can add it to our list."
#endif


int add_address (const char *ifname, struct in_addr address,
		 struct in_addr netmask, struct in_addr broadcast)
{
  char *daddress = strdup (inet_ntoa (address));
  logger (LOG_INFO, "adding IP address %s netmask %s",
	  daddress, inet_ntoa (netmask));
  free (daddress);

  return (do_address (ifname, address, netmask, broadcast, 0));
}

int del_address (const char *ifname, struct in_addr address)
{
  logger (LOG_INFO, "deleting IP address %s", inet_ntoa (address));

  struct in_addr t;
  memset (&t, 0, sizeof (t));
  return (do_address (ifname, address, t, t, 1));
}

/* This should work on all platforms */
int flush_addresses (const char *ifname)
{
  if (! ifname)
    return -1;

  struct ifaddrs *ifap;
  struct ifaddrs *p;

  if (getifaddrs (&ifap) != 0)
    return -1;

  for (p = ifap; p; p = p->ifa_next)
    {
      if (strcmp (p->ifa_name, ifname) != 0)
	continue;

      struct sockaddr_in *sin = (struct sockaddr_in*) p->ifa_addr;
      if (sin->sin_family == AF_INET)
	del_address (ifname, sin->sin_addr);
    }
  freeifaddrs (ifap);

  return 0;
}

int add_route (const char *ifname, struct in_addr destination,
	       struct in_addr netmask, struct in_addr gateway, int metric)
{
  return (do_route (ifname, destination, netmask, gateway, metric, 0, 0));
}

int change_route (const char *ifname, struct in_addr destination,
		  struct in_addr netmask, struct in_addr gateway, int metric)
{
  return (do_route (ifname, destination, netmask, gateway, metric, 1, 0));
}

int del_route (const char *ifname, struct in_addr destination,
	       struct in_addr netmask, struct in_addr gateway, int metric)
{
  return (do_route (ifname, destination, netmask, gateway, metric, 0, 1));
}

