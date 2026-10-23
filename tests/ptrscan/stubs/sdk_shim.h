/* Host build of ptr_scan.c: the libc / socket pieces the payload gets from the SDK. */
#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
extern long __crt_syscall(long sysno, ...);
int klog_puts(const char *s);
