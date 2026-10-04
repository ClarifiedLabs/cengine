#ifndef CENGINE_LIFECYCLE_XPC_H
#define CENGINE_LIFECYCLE_XPC_H
#include <stddef.h>
#include <stdint.h>
typedef struct ce_lifecycle_root ce_lifecycle_root;
typedef struct {
    uint64_t daemon_unique, child_unique;
    unsigned char daemon_audit[32], child_audit[32];
} ce_lifecycle_processes;
// Native observations only; never accepts process/audit DTOs.
int ce_lifecycle_parent(int fd, ce_lifecycle_processes *);
ce_lifecycle_root *ce_lifecycle_open(const void *greeting, size_t length);
int ce_lifecycle_next(ce_lifecycle_root *, void *, size_t, size_t *);
int ce_lifecycle_reply(ce_lifecycle_root *, const void *, size_t);
void ce_lifecycle_wait_closed(ce_lifecycle_root *);
void ce_lifecycle_cancel(ce_lifecycle_root *);
// Join all Go callers before destroying. Bounded failure leaks, never UAF.
void ce_lifecycle_destroy(ce_lifecycle_root *);
#endif
