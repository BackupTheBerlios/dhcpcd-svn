#include <syslog.h>

int LogLevel;

int log_to_level(const char *priority);
void logger(int level, const char *fmt, ...);
