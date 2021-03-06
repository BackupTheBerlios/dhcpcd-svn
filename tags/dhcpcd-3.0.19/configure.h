/*
 * dhcpcd - DHCP client daemon -
 * Copyright 2006-2007 Roy Marples <uberlord@gentoo.org>
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

#ifndef DHCPCONFIG_H
#define DHCPCONFIG_H

/* If you disable all 3 options you can shrink the binary by around 5-10k
   unstripped depending on platform and CFLAGS
   */
#define ENABLE_NTP
#define ENABLE_NIS
#define ENABLE_INFO

/* Define this to enable some compatability with 1.x and 2.x info files */
// #define ENABLE_INFO_COMPAT

#include "dhcpcd.h"
#include "interface.h"
#include "dhcp.h"

int configure (const options_t *options, interface_t *iface,
			   const dhcp_t *dhcp);

#endif
