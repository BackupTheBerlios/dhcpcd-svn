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

#include <string.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include "client.h"
#include "udpipgen.h"

extern	dhcpMessage	*DhcpMsgSend;
extern	dhcpOptions	DhcpOptions;
extern  dhcpInterface   DhcpIface;
extern	char		*HostName;
extern	int		HostName_len;
extern	int		BeRFC1541;
extern	unsigned	LeaseTime;
extern	int		TokenRingIf;
extern	unsigned char	ClientHwAddr[6];
extern  udpipMessage	UdpIpMsgSend;
extern  int 		magic_cookie;
extern  unsigned short  dhcpMsgSize;
extern  unsigned        nleaseTime;
extern  int             BroadcastResp;
extern  struct in_addr  inform_ipaddr;

extern	int		SetFQDNHostName;

/*****************************************************************************/
void buildDhcpDiscover(xid)
    unsigned xid;
{
  register unsigned char *p = DhcpMsgSend->options + 4;

  /* build Ethernet header */
  memset(&UdpIpMsgSend,0,sizeof(udpipMessage));
  memcpy(UdpIpMsgSend.ethhdr.ether_dhost,MAC_BCAST_ADDR,ETH_ALEN);
  memcpy(UdpIpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  UdpIpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_IP);

  DhcpMsgSend->op	=	DHCP_BOOTREQUEST;
  DhcpMsgSend->htype	=	(TokenRingIf) ? ARPHRD_IEEE802_TR : ARPHRD_ETHER;
  DhcpMsgSend->hlen	=	ETH_ALEN;
  DhcpMsgSend->xid	=	xid;
  DhcpMsgSend->secs	=       htons(10);
  if ( BroadcastResp )
    DhcpMsgSend->flags	=	htons(BROADCAST_FLAG);
#if 0
  memcpy(DhcpMsgSend->chaddr,DhcpIface.chaddr,ETH_ALEN);
#else
  memcpy(DhcpMsgSend->chaddr,ClientHwAddr,ETH_ALEN);
#endif
  memcpy(DhcpMsgSend->options,&magic_cookie,4);
  *p++ = dhcpMessageType;
  *p++ = 1;
  *p++ = DHCP_DISCOVER;
  *p++ = dhcpMaxMsgSize;
  *p++ = 2;
  memcpy(p,&dhcpMsgSize,2);
  p += 2;
  if ( DhcpIface.ciaddr )
    {
      if ( BeRFC1541 )
	DhcpMsgSend->ciaddr = DhcpIface.ciaddr;
      else
	{
	  *p++ = dhcpRequestedIPaddr;
	  *p++ = 4;
	  memcpy(p,&DhcpIface.ciaddr,4);
	  p += 4; 
	}
    }
  *p++ = dhcpIPaddrLeaseTime;
  *p++ = 4;
  memcpy(p,&nleaseTime,4);
  p += 4;
  *p++ = dhcpParamRequest;
  *p++ = 15;
  *p++ = subnetMask;
  *p++ = routersOnSubnet;
  *p++ = dns;
  *p++ = hostName;
  *p++ = domainName;
  *p++ = rootPath;
  *p++ = defaultIPTTL;
  *p++ = broadcastAddr;
  *p++ = performMaskDiscovery;
  *p++ = performRouterDiscovery;
  *p++ = staticRoute;
  *p++ = nisDomainName;
  *p++ = nisServers;
  *p++ = ntpServers;
  *p++ = dnsSearchPath;
  /* FQDN option (81) replaces HostName option (12) if requested */
  if (( HostName ) && ( SetFQDNHostName == FQDNdisable ))
    {
      *p++ = hostName;
      *p++ = HostName_len;
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
  *p++ = dhcpClassIdentifier;
  *p++ = DhcpIface.class_len;
  memcpy(p,DhcpIface.class_id,DhcpIface.class_len);
  p += DhcpIface.class_len;
  memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
  p += DhcpIface.client_len;
  if (( HostName ) && ( SetFQDNHostName != FQDNdisable ))
    {
      /* Draft IETF DHC-FQDN option (81) */
      *p++ = dhcpFQDNHostName;
      *p++ = HostName_len + 3;
      /* Flags: 0000NEOS
       * S: 1 => Client requests Server to update A RR in DNS as well as PTR
       * O: 1 => Server indicates to client that DNS has been updated regardless
       * E: 1 => Name data is DNS format, i.e. <4>host<6>domain<4>com<0> not "host.domain.com"
       * N: 1 => Client requests Server to not update DNS
       */
      *p++ = SetFQDNHostName & 0x9;
      *p++ = 0; /* rcode1, response from DNS server to DHCP for PTR RR */
      *p++ = 0; /* rcode2, response from DNS server to DHCP for A RR if S=1 */
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
  *p = endOption;

  /* build UDP/IP header */
  udpipgen((udpiphdr *)UdpIpMsgSend.udpipmsg,0,INADDR_BROADCAST,
	   htons(DHCP_CLIENT_PORT),htons(DHCP_SERVER_PORT),sizeof(dhcpMessage));
}
/*****************************************************************************/
void buildDhcpRequest(xid)
    unsigned xid;
{
  register unsigned char *p = DhcpMsgSend->options + 4;

  /* build Ethernet header */
  memset(&UdpIpMsgSend,0,sizeof(udpipMessage));
  memcpy(UdpIpMsgSend.ethhdr.ether_dhost,MAC_BCAST_ADDR,ETH_ALEN);
  memcpy(UdpIpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  UdpIpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_IP);

  DhcpMsgSend->op	=	DHCP_BOOTREQUEST;
  DhcpMsgSend->htype	=	(TokenRingIf) ? ARPHRD_IEEE802_TR : ARPHRD_ETHER;
  DhcpMsgSend->hlen	=	ETH_ALEN;
  DhcpMsgSend->xid	=	xid;
  DhcpMsgSend->secs	=	htons(10);
  if ( BroadcastResp )
    DhcpMsgSend->flags	=	htons(BROADCAST_FLAG);
#if 0
  memcpy(DhcpMsgSend->chaddr,DhcpIface.chaddr,ETH_ALEN);
#else
  memcpy(DhcpMsgSend->chaddr,ClientHwAddr,ETH_ALEN);
#endif
  memcpy(DhcpMsgSend->options,&magic_cookie,4);
  *p++ = dhcpMessageType;
  *p++ = 1;
  *p++ = DHCP_REQUEST;
  *p++ = dhcpMaxMsgSize;
  *p++ = 2;
  memcpy(p,&dhcpMsgSize,2);
  p += 2;
  *p++ = dhcpServerIdentifier;
  *p++ = 4;
  memcpy(p,DhcpOptions.val[dhcpServerIdentifier],4);
  p += 4;
  if ( BeRFC1541 )
    DhcpMsgSend->ciaddr = DhcpIface.ciaddr;
  else
    {
      *p++ = dhcpRequestedIPaddr;
      *p++ = 4;
      memcpy(p,&DhcpIface.ciaddr,4);
      p += 4;
    }
  if ( DhcpOptions.val[dhcpIPaddrLeaseTime] )
    {
      *p++ = dhcpIPaddrLeaseTime;
      *p++ = 4;
      memcpy(p,DhcpOptions.val[dhcpIPaddrLeaseTime],4);
      p += 4;
    }
  *p++ = dhcpParamRequest;
  *p++ = 15;
  *p++ = subnetMask;
  *p++ = routersOnSubnet;
  *p++ = dns;
  *p++ = hostName;
  *p++ = domainName;
  *p++ = rootPath;
  *p++ = defaultIPTTL;
  *p++ = broadcastAddr;
  *p++ = performMaskDiscovery;
  *p++ = performRouterDiscovery;
  *p++ = staticRoute;
  *p++ = nisDomainName;
  *p++ = nisServers;
  *p++ = ntpServers;
  *p++ = dnsSearchPath;
  /* FQDN option (81) replaces HostName option (12) if requested */
  if (( HostName ) && ( SetFQDNHostName == FQDNdisable ))
    {
      *p++ = hostName;
      *p++ = HostName_len;
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
  *p++ = dhcpClassIdentifier;
  *p++ = DhcpIface.class_len;
  memcpy(p,DhcpIface.class_id,DhcpIface.class_len);
  p += DhcpIface.class_len;
  memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
  p += DhcpIface.client_len;
  if (( HostName ) && ( SetFQDNHostName != FQDNdisable ))
    {
      /* Draft IETF DHC-FQDN option (81) */
      *p++ = dhcpFQDNHostName;
      *p++ = HostName_len + 3;
      /* Flags: 0000NEOS
       * S: 1 => Client requests Server to update A RR in DNS as well as PTR
       * O: 1 => Server indicates to client that DNS has been updated regardless
       * E: 1 => Name data is DNS format, i.e. <4>host<6>domain<4>com<0> not "host.domain.com"
       * N: 1 => Client requests Server to not update DNS
       */
      *p++ = SetFQDNHostName & 0x9;
      *p++ = 0; /* rcode1, response from DNS server to DHCP for PTR RR */
      *p++ = 0; /* rcode2, response from DNS server to DHCP for A RR if S=1 */
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
  *p = endOption;

  /* build UDP/IP header */
  udpipgen((udpiphdr *)UdpIpMsgSend.udpipmsg,0,INADDR_BROADCAST,
	   htons(DHCP_CLIENT_PORT),htons(DHCP_SERVER_PORT),sizeof(dhcpMessage));
}
/*****************************************************************************/
void buildDhcpRenew(xid)
    unsigned xid;
{
  register unsigned char *p = DhcpMsgSend->options + 4;
  memset(&UdpIpMsgSend,0,sizeof(udpipMessage));
  memcpy(UdpIpMsgSend.ethhdr.ether_dhost,DhcpIface.shaddr,ETH_ALEN);
  memcpy(UdpIpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  UdpIpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_IP);

  DhcpMsgSend->op	=	DHCP_BOOTREQUEST;
  DhcpMsgSend->htype	=	(TokenRingIf) ? ARPHRD_IEEE802_TR : ARPHRD_ETHER;
  DhcpMsgSend->hlen	=	ETH_ALEN;
  DhcpMsgSend->xid	=	xid;
  DhcpMsgSend->secs	=	htons(10);
  if ( BroadcastResp )
    DhcpMsgSend->flags	=	htons(BROADCAST_FLAG);
  DhcpMsgSend->ciaddr   =       DhcpIface.ciaddr;
#if 0
  memcpy(DhcpMsgSend->chaddr,DhcpIface.chaddr,ETH_ALEN);
#else
  memcpy(DhcpMsgSend->chaddr,ClientHwAddr,ETH_ALEN);
#endif
  memcpy(DhcpMsgSend->options,&magic_cookie,4);
  *p++ = dhcpMessageType;
  *p++ = 1;
  *p++ = DHCP_REQUEST;
  *p++ = dhcpMaxMsgSize;
  *p++ = 2;
  memcpy(p,&dhcpMsgSize,2);
  p += 2;
#if 0
  if ( DhcpOptions.val[dhcpIPaddrLeaseTime] )
    {
      *p++ = dhcpIPaddrLeaseTime;
      *p++ = 4;
      memcpy(p,DhcpOptions.val[dhcpIPaddrLeaseTime],4);
      p += 4;
    }
#endif
  *p++ = dhcpParamRequest;
  *p++ = 15;
  *p++ = subnetMask;
  *p++ = routersOnSubnet;
  *p++ = dns;
  *p++ = hostName;
  *p++ = domainName;
  *p++ = rootPath;
  *p++ = defaultIPTTL;
  *p++ = broadcastAddr;
  *p++ = performMaskDiscovery;
  *p++ = performRouterDiscovery;
  *p++ = staticRoute;
  *p++ = nisDomainName;
  *p++ = nisServers;
  *p++ = ntpServers;
  *p++ = dnsSearchPath;
  /* FQDN option (81) replaces HostName option (12) if requested */
  if (( HostName ) && ( SetFQDNHostName == FQDNdisable ))
    {
      *p++ = hostName;
      *p++ = HostName_len;
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
  *p++ = dhcpClassIdentifier;
  *p++ = DhcpIface.class_len;
  memcpy(p,DhcpIface.class_id,DhcpIface.class_len);
  p += DhcpIface.class_len;
  memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
  p += DhcpIface.client_len;
  if (( HostName ) && ( SetFQDNHostName != FQDNdisable ))
    {
      /* Draft IETF DHC-FQDN option (81) */
      *p++ = dhcpFQDNHostName;
      *p++ = HostName_len + 3;
      /* Flags: 0000NEOS
       * S: 1 => Client requests Server to update A RR in DNS as well as PTR
       * O: 1 => Server indicates to client that DNS has been updated regardless
       * E: 1 => Name data is DNS format, i.e. <4>host<6>domain<4>com<0> not "host.domain.com"
       * N: 1 => Client requests Server to not update DNS
       */
      *p++ = SetFQDNHostName & 0x9;
      *p++ = 0; /* rcode1, response from DNS server to DHCP for PTR RR */
      *p++ = 0; /* rcode2, response from DNS server to DHCP for A RR if S=1 */
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
  *p = endOption;

  udpipgen((udpiphdr *)UdpIpMsgSend.udpipmsg,
	   DhcpIface.ciaddr,DhcpIface.siaddr,
	   htons(DHCP_CLIENT_PORT),htons(DHCP_SERVER_PORT),sizeof(dhcpMessage));
}
/*****************************************************************************/
void buildDhcpRebind(xid)
    unsigned xid;
{
  register unsigned char *p = DhcpMsgSend->options + 4;
  memset(&UdpIpMsgSend,0,sizeof(udpipMessage));
  memcpy(UdpIpMsgSend.ethhdr.ether_dhost,MAC_BCAST_ADDR,ETH_ALEN);
  memcpy(UdpIpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  UdpIpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_IP);

  DhcpMsgSend->op	=	DHCP_BOOTREQUEST;
  DhcpMsgSend->htype	=	(TokenRingIf) ? ARPHRD_IEEE802_TR : ARPHRD_ETHER;
  DhcpMsgSend->hlen	=	ETH_ALEN;
  DhcpMsgSend->xid	=	xid;
  DhcpMsgSend->secs	=	htons(10);
  if ( BroadcastResp )
    DhcpMsgSend->flags	=	htons(BROADCAST_FLAG);
  DhcpMsgSend->ciaddr   =       DhcpIface.ciaddr;
#if 0
  memcpy(DhcpMsgSend->chaddr,DhcpIface.chaddr,ETH_ALEN);
#else
  memcpy(DhcpMsgSend->chaddr,ClientHwAddr,ETH_ALEN);
#endif
  memcpy(DhcpMsgSend->options,&magic_cookie,4);
  *p++ = dhcpMessageType;
  *p++ = 1;
  *p++ = DHCP_REQUEST;
  *p++ = dhcpMaxMsgSize;
  *p++ = 2;
  memcpy(p,&dhcpMsgSize,2);
  p += 2;
  if ( DhcpOptions.val[dhcpIPaddrLeaseTime] )
    {
      *p++ = dhcpIPaddrLeaseTime;
      *p++ = 4;
      memcpy(p,DhcpOptions.val[dhcpIPaddrLeaseTime],4);
      p += 4;
    }
  *p++ = dhcpParamRequest;
  *p++ = 15;
  *p++ = subnetMask;
  *p++ = routersOnSubnet;
  *p++ = dns;
  *p++ = hostName;
  *p++ = domainName;
  *p++ = rootPath;
  *p++ = defaultIPTTL;
  *p++ = broadcastAddr;
  *p++ = performMaskDiscovery;
  *p++ = performRouterDiscovery;
  *p++ = staticRoute;
  *p++ = nisDomainName;
  *p++ = nisServers;
  *p++ = ntpServers;
  *p++ = dnsSearchPath;
  /* FQDN option (81) replaces HostName option (12) if requested */
  if (( HostName ) && ( SetFQDNHostName == FQDNdisable ))
    {
      *p++ = hostName;
      *p++ = HostName_len;
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
  *p++ = dhcpClassIdentifier;
  *p++ = DhcpIface.class_len;
  memcpy(p,DhcpIface.class_id,DhcpIface.class_len);
  p += DhcpIface.class_len;
  memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
  p += DhcpIface.client_len;
  if (( HostName ) && ( SetFQDNHostName != FQDNdisable ))
    {
      /* Draft IETF DHC-FQDN option (81) */
      *p++ = dhcpFQDNHostName;
      *p++ = HostName_len + 3;
      /* Flags: 0000NEOS
       * S: 1 => Client requests Server to update A RR in DNS as well as PTR
       * O: 1 => Server indicates to client that DNS has been updated regardless
       * E: 1 => Name data is DNS format, i.e. <4>host<6>domain<4>com<0> not "host.domain.com"
       * N: 1 => Client requests Server to not update DNS
       */
      *p++ = SetFQDNHostName & 0x9;
      *p++ = 0; /* rcode1, response from DNS server to DHCP for PTR RR */
      *p++ = 0; /* rcode2, response from DNS server to DHCP for A RR if S=1 */
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
  *p = endOption;

  udpipgen((udpiphdr *)UdpIpMsgSend.udpipmsg,
	   DhcpIface.ciaddr,INADDR_BROADCAST,
	   htons(DHCP_CLIENT_PORT),htons(DHCP_SERVER_PORT),sizeof(dhcpMessage));
}
/*****************************************************************************/
void buildDhcpReboot(xid)
    unsigned xid;
{
  register unsigned char *p = DhcpMsgSend->options + 4;

  /* build Ethernet header */
  memset(&UdpIpMsgSend,0,sizeof(udpipMessage));
  memcpy(UdpIpMsgSend.ethhdr.ether_dhost,MAC_BCAST_ADDR,ETH_ALEN);
  memcpy(UdpIpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  UdpIpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_IP);

  DhcpMsgSend->op	=	DHCP_BOOTREQUEST;
  DhcpMsgSend->htype	=	(TokenRingIf) ? ARPHRD_IEEE802_TR : ARPHRD_ETHER;
  DhcpMsgSend->hlen	=	ETH_ALEN;
  DhcpMsgSend->xid	=	xid;
  DhcpMsgSend->secs	=	htons(10);
  if ( BroadcastResp )
    DhcpMsgSend->flags	=	htons(BROADCAST_FLAG);
#if 0
  memcpy(DhcpMsgSend->chaddr,DhcpIface.chaddr,ETH_ALEN);
#else
  memcpy(DhcpMsgSend->chaddr,ClientHwAddr,ETH_ALEN);
#endif
  memcpy(DhcpMsgSend->options,&magic_cookie,4);

  *p++ = dhcpMessageType;
  *p++ = 1;
  *p++ = DHCP_REQUEST;
  *p++ = dhcpMaxMsgSize;
  *p++ = 2;
  memcpy(p,&dhcpMsgSize,2);
  p += 2;
  if ( BeRFC1541 )
    DhcpMsgSend->ciaddr = DhcpIface.ciaddr;
  else
    {
      *p++ = dhcpRequestedIPaddr;
      *p++ = 4;
      memcpy(p,&DhcpIface.ciaddr,4);
      p += 4;
    }
  *p++ = dhcpIPaddrLeaseTime;
  *p++ = 4;
  memcpy(p,&nleaseTime,4);
  p += 4;
  *p++ = dhcpParamRequest;
  *p++ = 15;
  *p++ = subnetMask;
  *p++ = routersOnSubnet;
  *p++ = dns;
  *p++ = hostName;
  *p++ = domainName;
  *p++ = rootPath;
  *p++ = defaultIPTTL;
  *p++ = broadcastAddr;
  *p++ = performMaskDiscovery;
  *p++ = performRouterDiscovery;
  *p++ = staticRoute;
  *p++ = nisDomainName;
  *p++ = nisServers;
  *p++ = ntpServers;
  *p++ = dnsSearchPath;
  /* FQDN option (81) replaces HostName option (12) if requested */
  if (( HostName ) && ( SetFQDNHostName == FQDNdisable ))
    {
      *p++ = hostName;
      *p++ = HostName_len;
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
  *p++ = dhcpClassIdentifier;
  *p++ = DhcpIface.class_len;
  memcpy(p,DhcpIface.class_id,DhcpIface.class_len);
  p += DhcpIface.class_len;
  memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
  p += DhcpIface.client_len;
  if (( HostName ) && ( SetFQDNHostName != FQDNdisable ))
    {
      /* Draft IETF DHC-FQDN option (81) */
      *p++ = dhcpFQDNHostName;
      *p++ = HostName_len + 3;
      /* Flags: 0000NEOS
       * S: 1 => Client requests Server to update A RR in DNS as well as PTR
       * O: 1 => Server indicates to client that DNS has been updated regardless
       * E: 1 => Name data is DNS format, i.e. <4>host<6>domain<4>com<0> not "host.domain.com"
       * N: 1 => Client requests Server to not update DNS
       */
      *p++ = SetFQDNHostName & 0x9;
      *p++ = 0; /* rcode1, response from DNS server to DHCP for PTR RR */
      *p++ = 0; /* rcode2, response from DNS server to DHCP for A RR if S=1 */
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
  *p = endOption;

  udpipgen((udpiphdr *)UdpIpMsgSend.udpipmsg,0,INADDR_BROADCAST,
	   htons(DHCP_CLIENT_PORT),htons(DHCP_SERVER_PORT),sizeof(dhcpMessage));
}
/*****************************************************************************/
void buildDhcpRelease(xid)
    unsigned xid;
{
  register unsigned char *p = DhcpMsgSend->options + 4;
  memset(&UdpIpMsgSend,0,sizeof(udpipMessage));
  memcpy(UdpIpMsgSend.ethhdr.ether_dhost,DhcpIface.shaddr,ETH_ALEN);
  memcpy(UdpIpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  UdpIpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_IP);

  DhcpMsgSend->op	=	DHCP_BOOTREQUEST;
  DhcpMsgSend->htype	=	(TokenRingIf) ? ARPHRD_IEEE802_TR : ARPHRD_ETHER;
  DhcpMsgSend->hlen	=	ETH_ALEN;
  DhcpMsgSend->xid	=	xid;
  DhcpMsgSend->ciaddr	=	DhcpIface.ciaddr;
#if 0
  memcpy(DhcpMsgSend->chaddr,DhcpIface.chaddr,ETH_ALEN);
#else
  memcpy(DhcpMsgSend->chaddr,ClientHwAddr,ETH_ALEN);
#endif
  memcpy(DhcpMsgSend->options,&magic_cookie,4);
  *p++ = dhcpMessageType;
  *p++ = 1;
  *p++ = DHCP_RELEASE;
  *p++ = dhcpServerIdentifier;
  *p++ = 4;
  memcpy(p,DhcpOptions.val[dhcpServerIdentifier],4);
  p += 4;
  memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
  p += DhcpIface.client_len;
  *p = endOption;

  udpipgen((udpiphdr *)UdpIpMsgSend.udpipmsg,DhcpIface.ciaddr,
	   DhcpIface.siaddr,htons(DHCP_CLIENT_PORT),htons(DHCP_SERVER_PORT),
	   sizeof(dhcpMessage));
}
/*****************************************************************************/
void buildDhcpDecline(xid)
    unsigned xid;
{
  register unsigned char *p = DhcpMsgSend->options + 4;
  memset(&UdpIpMsgSend,0,sizeof(udpipMessage));
  memcpy(UdpIpMsgSend.ethhdr.ether_dhost,DhcpIface.shaddr,ETH_ALEN);
  memcpy(UdpIpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  UdpIpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_IP);

  DhcpMsgSend->op	=	DHCP_BOOTREQUEST;
  DhcpMsgSend->htype	=	(TokenRingIf) ? ARPHRD_IEEE802_TR : ARPHRD_ETHER;
  DhcpMsgSend->hlen	=	ETH_ALEN;
  DhcpMsgSend->xid	=	xid;
#if 0
  memcpy(DhcpMsgSend->chaddr,DhcpIface.chaddr,ETH_ALEN);
#else
  memcpy(DhcpMsgSend->chaddr,ClientHwAddr,ETH_ALEN);
#endif
  memcpy(DhcpMsgSend->options,&magic_cookie,4);
  *p++ = dhcpMessageType;
  *p++ = 1;
  *p++ = DHCP_DECLINE;
  *p++ = dhcpServerIdentifier;
  *p++ = 4;
  memcpy(p,DhcpOptions.val[dhcpServerIdentifier],4);
  p += 4;
  if ( BeRFC1541 )
    DhcpMsgSend->ciaddr = DhcpIface.ciaddr;
  else
    {
      *p++ = dhcpRequestedIPaddr;
      *p++ = 4;
      memcpy(p,&DhcpIface.ciaddr,4);
      p += 4;
    }
  memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
  p += DhcpIface.client_len;
  *p = endOption;

  udpipgen((udpiphdr *)UdpIpMsgSend.udpipmsg,0,
	   DhcpIface.siaddr,htons(DHCP_CLIENT_PORT),htons(DHCP_SERVER_PORT),
	   sizeof(dhcpMessage));
}
/*****************************************************************************/
void buildDhcpInform(xid)
    unsigned xid;
{
  register unsigned char *p = DhcpMsgSend->options + 4;

  memset(&UdpIpMsgSend,0,sizeof(udpipMessage));
  memcpy(UdpIpMsgSend.ethhdr.ether_dhost,MAC_BCAST_ADDR,ETH_ALEN);
  memcpy(UdpIpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  UdpIpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_IP);

  DhcpMsgSend->op	=	DHCP_BOOTREQUEST;
  DhcpMsgSend->htype	=	(TokenRingIf) ? ARPHRD_IEEE802_TR : ARPHRD_ETHER;
  DhcpMsgSend->hlen	=	ETH_ALEN;
  DhcpMsgSend->xid	=	xid;
  DhcpMsgSend->secs	=       htons(10);
  if ( BroadcastResp )
    DhcpMsgSend->flags	=	htons(BROADCAST_FLAG);
#if 0
  memcpy(DhcpMsgSend->chaddr,DhcpIface.chaddr,ETH_ALEN);
#else
  memcpy(DhcpMsgSend->chaddr,ClientHwAddr,ETH_ALEN);
#endif
  DhcpMsgSend->ciaddr = inform_ipaddr.s_addr;
  memcpy(DhcpMsgSend->options,&magic_cookie,4);
  *p++ = dhcpMessageType;
  *p++ = 1;
  *p++ = DHCP_INFORM;
  *p++ = dhcpMaxMsgSize;
  *p++ = 2;
  memcpy(p,&dhcpMsgSize,2);
  p += 2;
  *p++ = dhcpParamRequest;
  *p++ = 15;
  *p++ = subnetMask;
  *p++ = routersOnSubnet;
  *p++ = dns;
  *p++ = hostName;
  *p++ = domainName;
  *p++ = rootPath;
  *p++ = defaultIPTTL;
  *p++ = broadcastAddr;
  *p++ = performMaskDiscovery;
  *p++ = performRouterDiscovery;
  *p++ = staticRoute;
  *p++ = nisDomainName;
  *p++ = nisServers;
  *p++ = ntpServers;
  *p++ = dnsSearchPath;
  /* FQDN option (81) replaces HostName option (12) if requested */
  if (( HostName ) && ( SetFQDNHostName == FQDNdisable ))
    {
      *p++ = hostName;
      *p++ = HostName_len;
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
  *p++ = dhcpClassIdentifier;
  *p++ = DhcpIface.class_len;
  memcpy(p,DhcpIface.class_id,DhcpIface.class_len);
  p += DhcpIface.class_len;
  memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
  p += DhcpIface.client_len;
  if (( HostName ) && ( SetFQDNHostName != FQDNdisable ))
    {
      /* Draft IETF DHC-FQDN option (81) */
      *p++ = dhcpFQDNHostName;
      *p++ = HostName_len + 3;
      /* Flags: 0000NEOS
       * S: 1 => Client requests Server to update A RR in DNS as well as PTR
       * O: 1 => Server indicates to client that DNS has been updated regardless
       * E: 1 => Name data is DNS format, i.e. <4>host<6>domain<4>com<0> not "host.domain.com"
       * N: 1 => Client requests Server to not update DNS
       */
      *p++ = SetFQDNHostName & 0x9;
      *p++ = 0; /* rcode1, response from DNS server to DHCP for PTR RR */
      *p++ = 0; /* rcode2, response from DNS server to DHCP for A RR if S=1 */
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
  *p = endOption;

  udpipgen((udpiphdr *)UdpIpMsgSend.udpipmsg,0,INADDR_BROADCAST,
	   htons(DHCP_CLIENT_PORT),htons(DHCP_SERVER_PORT),sizeof(dhcpMessage));
}
