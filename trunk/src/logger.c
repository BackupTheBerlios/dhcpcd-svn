/*
 * Logging code
 * Copyright 2006 Roy Marples (uberlord@gentoo.org)
 */

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

extern int Daemonized;
int LogLevel = LOG_WARNING;

static char *syslog_level_msg[] = {
  [LOG_EMERG]   = "EMERGENCY!",
  [LOG_ALERT]   = "ALERT!",
  [LOG_CRIT]    = "Critical!",
  [LOG_WARNING] = "Warning",
  [LOG_ERR]     = "Error",
  [LOG_INFO]    = "Info",
  [LOG_DEBUG]   = "Debug"
};

static char *syslog_level[] = {
  [LOG_EMERG]   = "LOG_EMERG",
  [LOG_ALERT]   = "LOG_ALERT",
  [LOG_CRIT]    = "LOG_CRIT",
  [LOG_ERR]     = "LOG_ERR",
  [LOG_WARNING] = "LOG_WARNING",
  [LOG_NOTICE]  = "LOG_NOTICE",
  [LOG_INFO]    = "LOG_INFO",
  [LOG_DEBUG]   = "LOG_DEBUG"
};

int log_to_level(const char *priority)
{
  int i = 0;
  while (syslog_level[i]) {
	if (!strcmp(priority, syslog_level[i])) return i;
	i++;
  }
  return -1;
}

void logger(int level, const char *fmt, ...)
{
  va_list p;
  va_list p2;
  FILE *f = stderr;

  va_start(p, fmt);
  va_copy(p2, p);
  if(!Daemonized && (level <= LOG_ERR || level <= LogLevel)) {
	if ( level == LOG_DEBUG || level == LOG_INFO )
	  f = stdout;
	fprintf(f, "%s, ", syslog_level_msg[level]);
	vfprintf(f, fmt, p);
	fputc('\n', f);
  }
  if (level < LOG_DEBUG || level <= LogLevel)
	vsyslog(level, fmt, p2);
  va_end(p);
}

// vim: set ts=4 :
