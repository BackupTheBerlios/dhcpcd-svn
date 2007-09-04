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

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#ifdef __linux__
# include <netinet/ether.h>
#endif
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "configure.h"
#include "dhcp.h"
#ifdef ENABLE_INFO
# include "info.h"
#endif
#include "interface.h"
#include "dhcpcd.h"
#include "logger.h"
#include "socket.h"

/* IMPORTANT: Ensure that the last parameter is NULL when calling */
static int exec_cmd (const char *cmd, const char *args, ...)
{
	va_list va;
	pid_t pid;
	char **argv;
	int n = 1;

	va_start (va, args);
	while (va_arg (va, char *) != NULL)
		n++;
	va_end (va);
	argv = xmalloc (sizeof (char *) * (n + 2));

	va_start (va, args);
	n = 2;
	argv[0] = (char *) cmd;
	argv[1] = (char *) args;
	while ((argv[n] = va_arg (va, char *)) != NULL)
		n++;
	va_end (va);

	if ((pid = vfork ()) == 0) {
		if (execv (cmd, argv) && errno != ENOENT)
			logger (LOG_ERR, "error executing \"%s\": %s",
					cmd, strerror (errno));
		_exit (0);
	} else if (pid == -1) {
		logger (LOG_ERR, "vfork: %s", strerror (errno));
		free (argv);
		return (-1);
	}

	free (argv);
	return (0);
}

static void exec_script (const char *script, const char *infofile,
						 const char *arg)
{
	struct stat buf;

	if (! script || ! infofile || ! arg)
		return;

	if (stat (script, &buf) == -1) {
		if (strcmp (script, DEFAULT_SCRIPT) != 0)
			logger (LOG_ERR, "`%s': %s", script, strerror (ENOENT));
		return;
	}

	logger (LOG_DEBUG, "exec \"%s\" \"%s\" \"%s\"", script, infofile, arg);
	exec_cmd (script, infofile, arg, (char *) NULL);
}

static int make_resolv (const char *ifname, const dhcp_t *dhcp)
{
	FILE *f;
	struct stat buf;
	char resolvconf[PATH_MAX] = {0};
	address_t *address;

#ifdef RESOLVCONF
	if (stat (RESOLVCONF, &buf) == 0) {
		logger (LOG_DEBUG, "sending DNS information to resolvconf");
		snprintf (resolvconf, PATH_MAX, RESOLVCONF" -a %s", ifname);
		f = popen (resolvconf, "w");

		if (! f)
			logger (LOG_ERR, "popen: %s", strerror (errno));
	} else
#endif
	{
		logger (LOG_DEBUG, "writing "RESOLVFILE);
		if (! (f = fopen(RESOLVFILE, "w")))
			logger (LOG_ERR, "fopen `%s': %s", RESOLVFILE, strerror (errno));
	}

	if (! f)
		return (-1);

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

	/* Refresh the local resolver */
	res_init ();
	return (0);
}

static void restore_resolv(const char *ifname)
{
#ifdef RESOLVCONF
	struct stat buf;

	if (stat (RESOLVCONF, &buf) == -1)
		return;

	logger (LOG_DEBUG, "removing information from resolvconf");
	exec_cmd (RESOLVCONF, "-d", ifname, (char *) NULL);
#endif
}

#ifdef ENABLE_NTP
static int _make_ntp (const char *file, const char *ifname, const dhcp_t *dhcp)
{
	FILE *f;
	address_t *address;
	char *a;
	char buffer[1024];
	int tomatch = 0;
	char *token;
	bool ntp = false;

	for (address = dhcp->ntpservers; address; address = address->next)
		tomatch++;

	/* Check that we really need to update the servers
	   We do this because ntp has to be restarted to work with a changed config */
	if (! (f = fopen (file, "r"))) {
		if (errno != ENOENT) {
			logger (LOG_ERR, "fopen `%s': %s", file, strerror (errno));
			return -1;
		}
	} else {
		memset (buffer, 0, sizeof (buffer));
		while (fgets (buffer, sizeof (buffer), f)) {
			a = buffer;
			token = strsep (&a, " ");
			if (! token || strcmp (token, "server") != 0)
				continue;

			if ((token = strsep (&a, " \n")) == NULL)
				continue;

			for (address = dhcp->ntpservers; address; address = address->next)
				if (strcmp (token, inet_ntoa (address->address)) == 0) {
					tomatch--;
					break;
				}

			if (tomatch == 0)
				break;
		}
		fclose (f);

		/* File has the same name servers that we do, so no need to restart ntp */
		if (tomatch == 0) {
			logger (LOG_DEBUG, "%s already configured, skipping", file);
			return 0;
		}
	}

	logger (LOG_DEBUG, "writing %s", file);
	if (! (f = fopen (file, "w"))) {
		logger (LOG_ERR, "fopen `%s': %s", file, strerror (errno));
		return -1;
	}

	fprintf (f, "# Generated by dhcpcd for interface %s\n", ifname);
#ifdef NTPFILE
	if (strcmp (file, NTPFILE) == 0) {
		ntp = true;
		fprintf (f, "restrict default noquery notrust nomodify\n");
		fprintf (f, "restrict 127.0.0.1\n");
	}
#endif

	for (address = dhcp->ntpservers; address; address = address->next) {
		a = inet_ntoa (address->address);
		if (ntp)
			fprintf (f, "restrict %s nomodify notrap noquery\n", a);
		fprintf (f, "server %s\n", a);
	}

	if (ntp) {
		fprintf (f, "driftfile " NTPDRIFTFILE "\n");
		fprintf (f, "logfile " NTPLOGFILE "\n");
	}
	fclose (f);

	return 1;
}

static int make_ntp (const char *ifname, const dhcp_t *dhcp)
{
	/* On some systems we have only have one ntp service, but we don't know
	   which configuration file we're using. So we need to write to both and
	   restart accordingly. */

	bool restart_ntp = false;
	bool restart_openntp = false;
	int retval = 0;

#ifdef NTPFILE
	if (_make_ntp (NTPFILE, ifname, dhcp) > 0)
		restart_ntp = true;
#endif

#ifdef OPENNTPFILE
	if (_make_ntp (OPENNTPFILE, ifname, dhcp) > 0)
		restart_openntp = true;
#endif

#ifdef NTPSERVICE
	if (restart_ntp)
		retval += exec_cmd (NTPSERVICE, NTPRESTARTARGS, (char *) NULL);
#endif

#if defined (NTPSERVICE) && defined (OPENNTPSERVICE)
	if (restart_openntp &&
		(strcmp (NTPSERVICE, OPENNTPSERVICE) != 0 || ! restart_ntp))
		retval += exec_cmd (OPENNTPSERVICE, OPENNTPRESTARTARGS, (char *) NULL);
#elif defined (OPENNTPSERVICE) && ! defined (NTPSERVICE)
	if (restart_openntp) 
		retval += exec_cmd (OPENNTPSERVICE, OPENNTPRESTARTARGS, (char *) NULL);
#endif

	return retval;
}
#endif

#ifdef ENABLE_NIS
static int make_nis (const char *ifname, const dhcp_t *dhcp)
{
	FILE *f;
	address_t *address;
	char prefix[256] = {0};

	logger (LOG_DEBUG, "writing "NISFILE);
	if (! (f = fopen(NISFILE, "w"))) {
		logger (LOG_ERR, "fopen `%s': %s", NISFILE, strerror (errno));
		return -1;
	}

	fprintf (f, "# Generated by dhcpcd for interface %s\n", ifname);
	if (dhcp->nisdomain) {
		setdomainname (dhcp->nisdomain, strlen (dhcp->nisdomain));

		if (dhcp->nisservers)
			snprintf (prefix, sizeof (prefix), "domain %s server", dhcp->nisdomain);
		else
			fprintf (f, "domain %s broadcast\n", dhcp->nisdomain);
	}
	else
		snprintf (prefix, sizeof (prefix), "%s", "ypserver");

	for (address = dhcp->nisservers; address; address = address->next)
		fprintf (f, "%s %s\n", prefix, inet_ntoa (address->address));

	fclose (f);

	exec_cmd (NISSERVICE, NISRESTARTARGS, (char *) NULL);
	return 0;
}
#endif

int configure (const options_t *options, interface_t *iface,
			   const dhcp_t *dhcp, bool up)
{
	route_t *route = NULL;
	route_t *new_route = NULL;
	route_t *old_route = NULL;
	char newhostname[MAXHOSTNAMELEN] = {0};
	char curhostname[MAXHOSTNAMELEN] = {0};

	if (! options || ! iface || ! dhcp)
		return (-1);

	if (dhcp->address.s_addr == 0)
		up = 0;

	/* Remove old routes
	   Always do this as the interface may have >1 address not added by us
	   so the routes we added may still exist */
	if (iface->previous_routes) {
		for (route = iface->previous_routes; route; route = route->next)
			if (route->destination.s_addr || options->dogateway) {
				int have = 0;
				if (up)
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

	/* If we aren't up, then reset the interface as much as we can */
	if (! up) {
		if (iface->previous_routes) {
			free_route (iface->previous_routes);
			iface->previous_routes = NULL;
		}

		/* Restore the original MTU value */
		if (iface->mtu && iface->previous_mtu != iface->mtu) {
			set_mtu (iface->name, iface->mtu);
			iface->previous_mtu = iface->mtu;
		}

#ifdef ENABLE_INFO
		/* If we haven't created an info file, do so now */
		if (! dhcp->frominfo)
			write_info (iface, dhcp, options, false);
#endif

		/* Only reset things if we had set them before */
		if (iface->previous_address.s_addr != 0) {
			if (! options->keep_address) {
				del_address (iface->name, iface->previous_address,
							 iface->previous_netmask);
				memset (&iface->previous_address, 0, sizeof (struct in_addr));
				memset (&iface->previous_netmask, 0, sizeof (struct in_addr));
			}
		}

		restore_resolv (iface->name);
		/* we currently don't have a resolvconf style programs for ntp/nis */

		exec_script (options->script, iface->infofile, "down");

		return (0);
	}

	/* Set the MTU requested.
	   If the DHCP server no longer sends one OR it's invalid then we restore
	   the original MTU */
	if (options->domtu) {
		unsigned short mtu = iface->mtu;
		if (dhcp->mtu)
			mtu = dhcp->mtu;

		if (mtu != iface->previous_mtu) {
			if (set_mtu (iface->name, mtu) == 0)
				iface->previous_mtu = mtu;
		}
	}

	/* This also changes netmask */
	if (! options->doinform || ! has_address (iface->name, dhcp->address))
		if (add_address (iface->name, dhcp->address, dhcp->netmask,
						 dhcp->broadcast) == -1 && errno != EEXIST)
			return (false);
	
	/* Now delete the old address if different */
	if (iface->previous_address.s_addr != dhcp->address.s_addr) {
		if (iface->previous_address.s_addr != 0 && ! options->keep_address)
			del_address (iface->name, iface->previous_address, iface->previous_netmask);
	}

#ifdef __linux__
	/* On linux, we need to change the subnet route to have our metric. */
	if (iface->previous_address.s_addr != dhcp->address.s_addr
		&& options->metric > 0 && dhcp->netmask.s_addr != INADDR_BROADCAST)
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
	if (dhcp->routes) {
		route_t *new_routes = NULL;
		int remember;

		for (route = dhcp->routes; route; route = route->next) {
			/* Don't set default routes if not asked to */
			if (route->destination.s_addr == 0 && route->netmask.s_addr == 0
				&& ! options->dogateway)
				continue;

			remember = add_route (iface->name, route->destination,
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

			if (remember >= 0) {
				if (! new_routes) {
					new_routes = xmalloc (sizeof (route_t));
					memset (new_routes, 0, sizeof (route_t));
					new_route = new_routes;
				} else {
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

#ifdef ENABLE_NTP
	if (options->dontp && dhcp->ntpservers)
		make_ntp(iface->name, dhcp);
#endif

#ifdef ENABLE_NIS
	if (options->donis && (dhcp->nisservers || dhcp->nisdomain))
		make_nis(iface->name, dhcp);
#endif

	/* Now we have made a resolv.conf we can obtain a hostname if we need it */
	if (options->dohostname && (! dhcp->hostname || options->dohostname > 3)) { 
		union {
			struct sockaddr sa;
			struct sockaddr_in sin;
		} su;
		socklen_t salen;
		char addr[NI_MAXHOST];
		struct addrinfo hints, *res;
		int result;

		salen = sizeof (struct sockaddr);
		memset (&su.sa, 0, salen);
		su.sin.sin_family = AF_INET;
		memcpy (&su.sin.sin_addr, &dhcp->address, sizeof (struct in_addr));

		logger (LOG_DEBUG, "Looking up hostname via DNS");
		if ((result = getnameinfo (&su.sa, salen, addr, sizeof (addr),
						 NULL, 0, NI_NAMEREQD)) != 0)
			logger (LOG_ERR, "Failed to lookup hostname via DNS: %s", gai_strerror (result));
		else {
			/* Check for a malicious PTR record */
			memset (&hints, 0, sizeof (hints));
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_flags = AI_NUMERICHOST;
			if (getaddrinfo (addr, "0", &hints, &res) == 0) {
				freeaddrinfo (res);
				addr[0] = '\0';
				logger (LOG_ERR, "malicious PTR record detected");
			} else if (*addr) {
				char *p = strchr (addr, '.');
				if (p) {
					switch (options->dohostname) {
						case 1: /* -H */
						case 4: /* -HHHH */
							break;
						case 2: /* -HH */
						case 5: /* -HHHHH */
							/* Strip out the domain if it matches */
							p++;
							if (*p && dhcp->dnssearch) {
								char *s = xstrdup (dhcp->dnssearch);
								char *sp = s;
								char *t;

								while ((t = strsep (&sp, " ")))
									if (strcmp (t, p) == 0) {
										*--p = '\0';
										break;
									}
								free (s);
							} else if (dhcp->dnsdomain) {
								if (strcmp (dhcp->dnsdomain, p) == 0)
									*--p = '\0';
							}
							break;
						case 3: /* -HHH */
						case 6: /* -HHHHHH */
							/* Just strip the domain */
							*p = '\0';
							break;
						default: /* Too many H! */
							break;
					}
				}
				strlcpy (newhostname, addr, sizeof (newhostname));
			}
		}
	}

	gethostname (curhostname, sizeof (curhostname));

	if (options->dohostname
		|| strlen (curhostname) == 0
		|| strcmp (curhostname, "(none)") == 0
		|| strcmp (curhostname, "localhost") == 0)
	{
		if (dhcp->hostname)
			strlcpy (newhostname, dhcp->hostname, sizeof (newhostname)); 

		if (*newhostname) {
			logger (LOG_INFO, "setting hostname to `%s'", newhostname);
			sethostname (newhostname, strlen (newhostname));
		}
	}

#ifdef ENABLE_INFO
	if (! dhcp->frominfo)
		write_info (iface, dhcp, options, true);
#endif

	if (iface->previous_address.s_addr != dhcp->address.s_addr ||
		iface->previous_netmask.s_addr != dhcp->netmask.s_addr)
	{
		memcpy (&iface->previous_address,
				&dhcp->address, sizeof (struct in_addr));
		memcpy (&iface->previous_netmask,
				&dhcp->netmask, sizeof (struct in_addr));
		exec_script (options->script, iface->infofile, "new");
	} else
		exec_script (options->script, iface->infofile, "up");

	return (0);
}

