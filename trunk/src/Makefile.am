EXTRA_DIST		=		\
	$(man_MANS)			\
	dhcpcd.exe

man_MANS		= @PACKAGE@.8

sbin_PROGRAMS		= dhcpcd 

dhcpcd_SOURCES		=	\
	logger.c		\
	logger.h		\
	peekfd.c		\
	udpipgen.c		\
	buildmsg.c		\
	signals.c		\
	arp.c			\
	dhcpconfig.c		\
	client.c		\
	cache.c			\
	dhcpcd.c		\
	signals.h		\
	buildmsg.h		\
	client.h		\
	dhcpcd.h		\
	pathnames.h		\
	signals.h		\
	kversion.h		\
	udpipgen.h

configdir		= ${sysconfdir}/dhcpc
config_DATA		= dhcpcd.exe
