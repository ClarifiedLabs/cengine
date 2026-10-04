/* Fixed Linux/glibc configuration for the pinned builder; no autotools needed. */
#define _GNU_SOURCE 1
#define HAVE_SYS_SYSMACROS_H 1
#define HAVE_STRUCT_STAT_ST_ATIM 1
#define HAVE_STRUCT_STAT_ST_MTIM 1
#define HAVE_STRUCT_STAT_ST_CTIM 1
