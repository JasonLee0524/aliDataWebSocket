#ifndef __OS__
#define __OS__


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "aliwebdll.h"
#if defined LINUX_NET
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif
#if defined LWIP_NET
#include "lwip/sockets.h"
#endif

#endif