/*
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 * Copyright (C) 1998 Sergei Viznyuk <sv@phystech.com>
 *
 * Dhcpcd is an RFC2131 and RFC1541 compliant DHCP client daemon.
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

#ifndef PATHNAMES_H
#define PATHNAMES_H

#include <paths.h>
#include "dhcpcd.h"

#define CACHE_DIR		"/var/cache"
#define PID_FILE_PATH		"%.0s/var/run/"PROGRAM_NAME"-%s.pid"
#define DHCP_CACHE_FILE		"%s/"PROGRAM_NAME"-%s.cache"
#define DHCP_HOSTINFO		"%s/"PROGRAM_NAME"-%s.info"
#define EXEC_ON_CHANGE		"%.0s/etc/dhcpc/"PROGRAM_NAME".exe"

#ifdef EMBED
#define ETC_DIR			"/etc/config"
#define CONFIG_DIR		"/etc/config/dhcpc"
#else
#define ETC_DIR			"/etc"
#define CONFIG_DIR		"/var/lib/dhcpc"
#endif

#define RESOLV_FILE		"%s/resolv.conf"
#define NIS_FILE		"%s/yp.conf"
#define NTP_FILE		"%s/ntp.conf"

#endif
