#ifndef CLI_H
#define CLI_H
#include "common.h"
#include "hash_chain.h"
#include "log_listener.h"
#include "storage.h"
#include "sig_verify.h"
#include "tpm_nv.h"
#include "tpm_signer.h"
#include "verification.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int file_exists(const char *path);
int do_append(const char *text);
int do_verify(void);
int do_verify_sig();
int do_head(void);
int do_nv_read_head(void);

#endif
