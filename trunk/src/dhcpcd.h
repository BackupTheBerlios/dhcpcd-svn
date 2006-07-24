/*
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 * Copyright (C) January, 1998 Sergei Viznyuk <sv@phystech.com>
 * Copyright (C) 2005 - 2006 Roy Marples <uberlord@gentoo.org>
 * Copyright (C) 2005 - 2006 Simon Kelley <simon@thekelleys.org.uk>
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

#ifndef DHCPCD_H
#define DHCPCD_H

#define DEFAULT_IFNAME		"eth0"
#define DEFAULT_IFNAME_LEN	4
#define DEFAULT_TIMEOUT		60
#define DEFAULT_LEASETIME	0xffffffff      /* infinite lease time */

extern	char		*ProgramName;
extern	char		*IfName,*IfNameExt;
extern	int		IfName_len,IfNameExt_len;
extern struct in_addr	default_router;
extern	char		*HostName;
extern	unsigned char	*ClassID;
extern	int		ClassID_len;
extern  unsigned char	*ClientID;
extern  int		ClientID_len;
extern	int		BeRFC1541;
extern	unsigned	LeaseTime;
extern	int		SetDomainName;
extern	int		SetHostName;
extern	int		SendSecondDiscover;
extern	unsigned short	ip_id;
extern  void		*(*currState)();
extern  time_t          TimeOut;
extern  unsigned        nleaseTime;
extern  struct in_addr  inform_ipaddr;
extern	int		TestCase;
extern	int		resolv_renamed,yp_renamed,ntp_renamed;
extern	int		DownIfaceOnStop;
extern  int		DoARP;
extern	char		*Cfilename;
extern	int		ReplResolvConf;
extern	int		ReplNISConf;
extern	int		ReplNTPConf;
extern  int		RouteMetric;
extern	int		Window;
extern  char            **ProgramEnviron;
extern  int		SetDHCPDefaultRoutes;
extern  char		*ConfigDir;

extern	char		resolv_file[128];
extern	char		resolv_file_sv[128];
extern	char		ntp_file[128];
extern	char		ntp_file_sv[128];
extern	char		nis_file[128];
extern	char		nis_file_sv[128];

extern	int		SetFQDNHostName;

#endif
