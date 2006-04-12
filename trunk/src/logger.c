/*
 * Logging code
 * Copyright 2006 Roy Marples (uberlord@gentoo.org)
 */

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

extern int Daemonized;
extern int DebugFlag;
extern int VerboseFlag;

static char *syslog_level_msg[] = {
        [LOG_EMERG]   = "EMERGENCY!",
        [LOG_ALERT]   = "ALERT!",
        [LOG_CRIT]    = "Critical!",
        [LOG_WARNING] = "Warning",
        [LOG_ERR]     = "Error",
        [LOG_INFO]    = "Info",
        [LOG_DEBUG]   = "Debug"
};

void logger(int level, const char *fmt, ...)
{
	va_list p;
	va_list p2;
	FILE *f = stderr;

	va_start(p, fmt);
	va_copy(p2, p);
	if(!Daemonized && (DebugFlag || level <= LOG_ERR 
				|| (VerboseFlag && level == LOG_INFO))) {
		if ( level == LOG_DEBUG || level == LOG_INFO )
			f = stdout;
		fprintf(f, "%s, ", syslog_level_msg[level]);
		vfprintf(f, fmt, p);
		fputc('\n', f);
	}
	if (level < LOG_DEBUG || DebugFlag)
		vsyslog(level, fmt, p2);
	va_end(p);
}

// vim: set ts=4 :
