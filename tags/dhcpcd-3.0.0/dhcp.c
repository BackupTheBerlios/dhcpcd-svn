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

#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <net/if_arp.h>

#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "dhcp.h"
#include "interface.h"
#include "logger.h"
#include "socket.h"

static char *dhcp_message[] = {
  [DHCP_DISCOVER] 	= "DHCP_DISCOVER",
  [DHCP_OFFER]		= "DHCP_OFFER",
  [DHCP_REQUEST]	= "DHCP_REQUEST",
  [DHCP_DECLINE]	= "DHCP_DECLINE",
  [DHCP_ACK]		= "DHCP_ACK",
  [DHCP_NAK]		= "DHCP_NAK",
  [DHCP_RELEASE]	= "DHCP_RELEASE",
  [DHCP_INFORM]		= "DHCP_INFORM",
  [DHCP_INFORM + 1]	= NULL
};

size_t send_message (interface_t *iface, dhcp_t *dhcp,
		     unsigned long xid, char type, options_t *options)
{
  dhcpmessage_t message;
  unsigned char *p = (unsigned char *) &message.options;
  unsigned char *n_params = NULL;
  unsigned long l;

  if (!iface || !options || !dhcp)
    return -1;

  memset (&message, 0, sizeof (dhcpmessage_t));

  message.op = DHCP_BOOTREQUEST;
  message.hwtype = ARPHRD_ETHER;
  message.hwlen = ETHER_ADDR_LEN;
  message.secs = htons (10);
  message.xid = xid;
  memcpy (&message.hwaddr, &iface->ethernet_address, ETHER_ADDR_LEN);
  message.cookie = htonl(MAGIC_COOKIE);

  if (iface->previous_address.s_addr != 0 &&
      iface->previous_address.s_addr == dhcp->address.s_addr)
    message.ciaddr = iface->previous_address.s_addr; 

  *p++ = DHCP_MESSAGETYPE; 
  *p++ = 1;
  *p++ = type;

  if (type == DHCP_REQUEST)
    {
      *p++ = DHCP_MAXMESSAGESIZE;
      *p++ = 2;
      uint16_t sz = htons (sizeof (struct udp_dhcp_packet));
      memcpy (p, &sz, 2);
      p += 2;
    }

  if (dhcp->address.s_addr != 0 && iface->previous_address.s_addr == 0)
    {
      *p++ = DHCP_ADDRESS;
      *p++ = 4;
      memcpy (p, &dhcp->address.s_addr, 4);
      p += 4;
    }

  if (dhcp->serveraddress.s_addr != 0 && dhcp->address.s_addr !=0 &&
      iface->previous_address.s_addr == 0)
    {
      *p++ = DHCP_SERVERIDENTIFIER;
      *p++ = 4;
      memcpy (p, &dhcp->serveraddress.s_addr, 4);
      p += 4;

      /* Blank out the server address so we broadcast */
      if (type == DHCP_REQUEST) dhcp->serveraddress.s_addr = 0;
    }

  if (type == DHCP_REQUEST || type == DHCP_DISCOVER)
    {
      if (dhcp->leasetime > 0)
	{
	  *p++ = DHCP_LEASETIME;
	  *p++ = 4;
	  uint32_t ul = htonl (dhcp->leasetime);
	  memcpy (p, &ul, 4);
	  p += 4;
	}
    }

  *p++ = DHCP_PARAMETERREQUESTLIST;
  n_params = p;
  *p++ = 0;

  if (type == DHCP_REQUEST)
    {
      *p++ = DHCP_RENEWALTIME;
      *p++ = DHCP_REBINDTIME;
      *p++ = DHCP_NETMASK;
      *p++ = DHCP_BROADCAST;
      *p++ = DHCP_CSR;
      /* RFC 3442 states classless static routes should be before routers
       * and static routes as classless static routes override them both */
      *p++ = DHCP_ROUTERS;
      *p++ = DHCP_STATICROUTE;
      *p++ = DHCP_HOSTNAME;
      *p++ = DHCP_DNSSEARCH;
      *p++ = DHCP_DNSDOMAIN;
      *p++ = DHCP_DNSSERVER;
      *p++ = DHCP_NISDOMAIN;
      *p++ = DHCP_NISSERVER;
      *p++ = DHCP_NTPSERVER;
      /* These parameters were requested by dhcpcd-2.0 and earlier
	 but we never did anything with them */
      /*    *p++ = DHCP_DEFAULTIPTTL;
       *p++ = DHCP_MASKDISCOVERY;
       *p++ = DHCP_ROUTERDISCOVERY; */
    }
  else
    /* Always request one parameter so we don't get the server default
       when we don't actally need any at this time */
    *p++ = DHCP_DNSSERVER;

  *n_params = p - n_params - 1;

  if (type == DHCP_REQUEST)
    {
      if (options->hostname) 
	{
	  if (options->fqdn == FQDN_DISABLE)
	    {
	      *p++ = DHCP_HOSTNAME;
	      *p++ = l = strlen (options->hostname);
	      memcpy (p, options->hostname, l);
	      p += l;
	    }
	  else
	    {
	      /* Draft IETF DHC-FQDN option (81) */
	      *p++ = DHCP_FQDN;
	      *p++ = (l = strlen (options->hostname)) + 3;
	      /* Flags: 0000NEOS
	       * S: 1 => Client requests Server to update A RR in DNS as well as PTR
	       * O: 1 => Server indicates to client that DNS has been updated
	       * E: 1 => Name data is DNS format
	       * N: 1 => Client requests Server to not update DNS
	       */
	      *p++ = options->fqdn & 0x9;
	      *p++ = 0; /* rcode1, response from DNS server for PTR RR */
	      *p++ = 0; /* rcode2, response from DNS server for A RR if S=1 */
	      memcpy (p, options->hostname, l);
	      p += l;
	    }
	}
    }

  if (options->userclass)
    {
      *p++ = DHCP_USERCLASS;
      *p++ = l = strlen (options->userclass);
      memcpy (p, options->userclass, l);
      p += l;
    }

  *p++ = DHCP_CLASSID;
  *p++ = l = strlen (options->classid);
  memcpy (p, options->classid, l);
  p += l;

  *p++ = DHCP_CLIENTID;
  if (options->clientid[0])
    {
      l = strlen (options->clientid);
      *p++ = l + 1;
      *p++ = 0; /* string */
      memcpy (p, options, l);
      p += l;
    }
  else
    {
      *p++ = ETHER_ADDR_LEN + 1;
      *p++ = ARPHRD_ETHER;
      memcpy (p, &iface->ethernet_address, ETHER_ADDR_LEN);
      p += ETHER_ADDR_LEN;
    }

  *p = DHCP_END;

  struct udp_dhcp_packet packet;
  memset (&packet, 0, sizeof (struct udp_dhcp_packet));
  make_dhcp_packet (&packet, (unsigned char *) &message,
		    dhcp->address, dhcp->serveraddress);

  logger (LOG_DEBUG, "Sending %s with xid %d", dhcp_message[(int) type], xid);
  return send_packet (iface, ETHERTYPE_IP, (unsigned char *) &packet,
		      sizeof (struct udp_dhcp_packet));
}

static unsigned long getnetmask (unsigned long ip_in)
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

/* Decode an RFC3397 DNS search order option into a space
   seperated string. Returns length of string (including 
   terminating zero) or zero on error. out may be NULL
   to just determine output length. */
static unsigned int decode_search (u_char *p, int len, char *out)
{
  u_char *r, *q = p;
  unsigned int count = 0, l, hops;

  while (q - p < len)
    {
      r = NULL;
      hops = 0;
      while ((l = *q++))
	{
	  unsigned int label_type = l & 0xc0;
	  if (label_type == 0x80 || label_type == 0x40)
	    return 0;
	  else if (label_type == 0xc0) /* pointer */
	    { 
	      l = (l & 0x3f) << 8;
	      l |= *q++;

	      /* save source of first jump. */
	      if (!r)
		r = q;

	      hops++;
	      if (hops > 255)
		return 0;

	      q = p + l;
	      if (q - p >= len)
		return 0;
	    }
	  else 
	    {
	      /* straightforward name segment, add with '.' */
	      count += l + 1;
	      if (out)
		{
		  memcpy (out, q, l);
		  out += l;
		  *out++ = '.';
		}
	      q += l;
	    }
	}

      /* change last dot to space */
      if (out)
	*(out - 1) = ' ';

      if (r)
	q = r;
    }

  /* change last space to zero terminator */
  if (out)
    *(out - 1) = 0;

  return count;  
}

/* Add our classless static routes to the routes variable
 * and return the last route set */
static route_t *decodeCSR(unsigned char *p, int len)
{
  /* Minimum is 5 -first is CIDR and a router length of 4 */
  if (len < 5)
    return NULL;

  unsigned char *q = p;
  int cidr;
  int ocets;
  route_t *first = xmalloc (sizeof (route_t));
  route_t *route = first;

  while (q - p < len)
    {
      memset (route, 0, sizeof (route_t));

      cidr = (int) *q++;
      if (cidr == 0)
	ocets = 0;
      else if (cidr < 9)
	ocets = 1;
      else if (cidr < 17)
	ocets = 2;
      else if (cidr < 25)
	ocets = 3;
      else
	ocets = 4;

      if (ocets > 0)
	{
	  memcpy (&route->destination.s_addr, q, ocets);
	  q += ocets;
	}

      /* Now enter the netmask */
      if (ocets > 0)
	{
	  memset (&route->netmask.s_addr, 255, ocets - 1);
	  memset ((unsigned char *) &route->netmask.s_addr + (ocets - 1),
		  (256 - (1 << (32 - cidr) % 8)), 1);
	}

      /* Finally, snag the router */
      memcpy (&route->gateway.s_addr, q, 4);
      q += 4;

      /* We have another route */
      if (q - p < len)
	{
	  route->next = xmalloc (sizeof (route_t));
	  route = route->next;
	}
    }

  return first;
}

void free_dhcp (dhcp_t *dhcp)
{
  if (!dhcp)
    return;

  if (dhcp->routes)
    free_route (dhcp->routes);

  if (dhcp->hostname)
    free (dhcp->hostname);

  if (dhcp->dnsservers)
    free_address (dhcp->dnsservers);
  if (dhcp->dnsdomain)
    free (dhcp->dnsdomain);
  if (dhcp->dnssearch)
    free (dhcp->dnssearch);

  if (dhcp->ntpservers)
    free_address (dhcp->ntpservers);

  if (dhcp->nisdomain)
    free (dhcp->nisdomain);
  if (dhcp->nisservers)
    free_address (dhcp->nisservers);

  if (dhcp->rootpath)
    free (dhcp->rootpath);

  if (dhcp->fqdn)
    {
      if (dhcp->fqdn->name)
	free (dhcp->fqdn->name);
      free (dhcp->fqdn);
    }
}

static void dhcp_add_address(address_t *address, unsigned char *data, int length)
{
  int i;
  address_t *p = address;

  for (i = 0; i < length; i += 4)
    {
      memset (p, 0, sizeof (address_t));
      memcpy (&p->address.s_addr, data + i, 4);
      if (length - i > 4)
	{
	  p->next = xmalloc (sizeof (address_t));
	  p = p->next;
	}
    }
}

int parse_dhcpmessage (dhcp_t *dhcp, dhcpmessage_t *message)
{
  unsigned char *p = message->options;
  unsigned char option;
  unsigned char length;
  unsigned char *end = message->options + sizeof (message->options);
  unsigned int len = 0;
  int i;
  int retval = -1;
  route_t *first_route = xmalloc (sizeof (route_t));
  route_t *route = first_route;
  route_t *last_route = NULL;
  route_t *csr = NULL;
  char classid[CLASS_ID_MAX_LEN];
  char clientid[CLIENT_ID_MAX_LEN];

  memset (first_route, 0, sizeof (route_t));

  /* The message back never has the class or client id's so we save them */
  strcpy (classid, dhcp->classid);
  strcpy (clientid, dhcp->clientid);

  free_dhcp (dhcp);
  memset (dhcp, 0, sizeof (dhcp_t));

  dhcp->address.s_addr = message->yiaddr;
  strcpy (dhcp->servername, message->servername);

  while (p < end)
    {
      option = *p++;
      if (!option)
	continue;

      length = *p++;

      if (p + length >= end)
	{
	  retval = -1;
	  goto eexit;
	}

      switch (option)
	{
	case DHCP_END:
	  goto eexit;

	case DHCP_MESSAGETYPE:
	  retval = (int) *p;
	  break;

	case DHCP_ADDRESS:
	  memcpy (&dhcp->address.s_addr, p, 4);
	  break;
	case DHCP_NETMASK:
	  memcpy (&dhcp->netmask.s_addr, p, 4);
	  break;
	case DHCP_BROADCAST:
	  memcpy (&dhcp->broadcast.s_addr, p, 4);
	  break;
	case DHCP_SERVERIDENTIFIER:
	  memcpy (&dhcp->serveraddress.s_addr, p, 4);
	  break;

	case DHCP_LEASETIME:
	  dhcp->leasetime = ntohl (* (uint32_t *) p);
	  break;
	case DHCP_RENEWALTIME:
	  dhcp->renewaltime = ntohl (* (uint32_t *) p);
	  break;
	case DHCP_REBINDTIME:
	  dhcp->rebindtime = ntohl (* (uint32_t *) p);
	  break;
	case DHCP_MTU:
	  dhcp->mtu = ntohs (* (uint16_t *) p);
	  /* Minimum legal mtu is 68 */
	  if (dhcp->mtu > 0 && dhcp->mtu < 68)
	    dhcp->mtu = 68;
	  break;

	case DHCP_HOSTNAME:
	  if (dhcp->hostname)
	    free (dhcp->hostname);
	  dhcp->hostname = xmalloc (length + 1);
	  memcpy (dhcp->hostname, p, length);
	  dhcp->hostname[length] = '\0';
	  break;

	case DHCP_DNSDOMAIN:
	  if (dhcp->dnsdomain)
	    free (dhcp->dnsdomain);
	  dhcp->dnsdomain = xmalloc (length + 1);
	  memcpy (dhcp->dnsdomain, p, length);
	  dhcp->dnsdomain[length] = '\0';
	  break;

	case DHCP_MESSAGE:
	  if (dhcp->message)
	    free (dhcp->message);
	  dhcp->message = xmalloc (length + 1);
	  memcpy (dhcp->message, p, length);
	  dhcp->message[length] = '\0';
	  break;

	case DHCP_ROOTPATH:
	  if (dhcp->rootpath)
	    free (dhcp->rootpath);
	  dhcp->rootpath = xmalloc (length + 1);
	  memcpy (dhcp->rootpath, p, length);
	  dhcp->rootpath[length] = '\0';
	  break;

	case DHCP_NISDOMAIN:
	  if (dhcp->nisdomain)
	    free (dhcp->nisdomain);
	  dhcp->nisdomain = xmalloc (length + 1);
	  memcpy (dhcp->nisdomain, p, length);
	  dhcp->nisdomain[length] = '\0';
	  break;

	case DHCP_DNSSERVER:
	  if (dhcp->dnsservers)
	    free_address (dhcp->dnsservers);
	  dhcp->dnsservers = xmalloc (sizeof (address_t));
	  dhcp_add_address (dhcp->dnsservers, p, length);
	  break;
	case DHCP_NTPSERVER:
	  if (dhcp->ntpservers)
	    free_address (dhcp->ntpservers);
	  dhcp->ntpservers = xmalloc (sizeof (address_t));
	  dhcp_add_address (dhcp->ntpservers, p, length);
	  break;
	case DHCP_NISSERVER:
	  if (dhcp->nisservers)
	    free_address (dhcp->nisservers);
	  dhcp->nisservers = xmalloc (sizeof (address_t));
	  dhcp_add_address (dhcp->nisservers, p, length);
	  break;

	case DHCP_DNSSEARCH:
	  if (dhcp->dnssearch)
	    free (dhcp->dnssearch);
	  if ((len = decode_search (p, length, NULL)))
	    {
	      dhcp->dnssearch = xmalloc (len);
	      decode_search (p, length, dhcp->dnssearch);
	    }
	  break;

	case DHCP_CSR:
	  csr = decodeCSR (p, length);
	  break;

	case DHCP_STATICROUTE:
	  for (i = 0; i < length; i += 8)
	    {
	      memcpy (&route->destination.s_addr, p + i, 4);
	      memcpy (&route->gateway.s_addr, p + i + 4, 4);
	      route->netmask.s_addr = getnetmask (route->destination.s_addr); 
	      last_route = route;
	      route->next = xmalloc (sizeof (route_t));
	      route = route->next;
	      memset (route, 0, sizeof (route_t));
	    }
	  break;

	case DHCP_ROUTERS:
	  for (i = 0; i < length; i += 4)
	    {
	      memcpy (&route->gateway.s_addr, p + i, 4);
	      last_route = route;
	      route->next = xmalloc (sizeof (route_t));
	      route = route->next;
	      memset (route, 0, sizeof (route_t));
	    }
	  break;

	default:
	  logger (LOG_DEBUG, "no facility to parse DHCP code %u", option);
	  break;
	}

      p += length;
    }

eexit:
  /* Fill in any missing fields */
  if (!dhcp->netmask.s_addr)
    dhcp->netmask.s_addr = getnetmask (dhcp->address.s_addr);
  if (!dhcp->broadcast.s_addr)
    dhcp->broadcast.s_addr = dhcp->address.s_addr | ~dhcp->netmask.s_addr;

  /* If we have classess static routes then we discard
     static routes and routers according to RFC 3442 */
  if (csr)
    {
      dhcp->routes = csr;
      free_route (first_route); 
    }
  else
    {
      dhcp->routes = first_route;
      if (last_route)
	{
	  free (last_route->next);
	  last_route->next = NULL;
	}
      else
	{
	  free_route (dhcp->routes);
	  dhcp->routes = NULL;
	}
    }

  /* The message back never has the class or client id's so we restore them */
  strcpy (dhcp->classid, classid);
  strcpy (dhcp->clientid, clientid);

  return retval;
}

