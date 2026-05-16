#ifndef MONOLITH_FILE_H
#define MONOLITH_FILE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

int fileexists(const char *path);
int filesize(const char *path, uint64_t *out);
int slurp(const char *path, uint8_t **buf, size_t *len);
int spit(const char *path, const uint8_t *buf, size_t len);

#endif
