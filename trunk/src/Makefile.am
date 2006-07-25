EXTRA_DIST		=		\
	$(man_MANS)			\
	dhcpcd.exe

man_MANS		= @PACKAGE@.8

sbin_PROGRAMS		= dhcpcd 

dhcpcd_SOURCES		=	\
	logger.c		\
	logger.h		\
	peekfd.c		\
	peekfd.h		\
	udpipgen.c		\
	udpipgen.h		\
	buildmsg.c		\
	buildmsg.h		\
	signals.c		\
	signals.h		\
	arp.c			\
	arp.h			\
	dhcpconfig.c		\
	client.c		\
	client.h		\
	cache.c			\
	cache.h			\
	dhcpcd.c		\
	dhcpcd.h		\
	pathnames.h		

configdir		= ${sysconfdir}/dhcpc
config_DATA		= dhcpcd.exe
