#ifndef KIT_H
#define KIT_H

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <SDL2/SDL.h>
#include <unistd.h>


typedef void *ptr; //I do like pointers

#include "declarations.h"

extern char exitbool;
extern unsigned long lps;

#define FILENAME __FILE_NAME__

#define None 0
#define false 0
#define true 1
#define max(x,y) (x>y?x:y)
#define min(x,y) (x<y?x:y)
#define LOG(fmt, ...) printf("[%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

// This macro wasn't made by me ._. but I do need it
#define DEBUG(x) \
    _Generic((x), \
        short:          LOG(#x ": %hd", (x)), \
        unsigned short: LOG(#x ": %hu", (x)), \
        int:            LOG(#x ": %d", (x)), \
        unsigned int:   LOG(#x ": %u", (x)), \
        long:           LOG(#x ": %ld", (x)), \
        unsigned long:  LOG(#x ": %lu", (x)), \
        long long:      LOG(#x ": %lld", (x)), \
        unsigned long long: LOG(#x ": %llu", (x)), \
        float:          LOG(#x ": %f", (x)), \
        double:         LOG(#x ": %lf", (x)), \
        char:           LOG(#x ": '%c'", (x)), \
        char *:         LOG(#x ": \"%s\"", (x)), \
        const char *:   LOG(#x ": \"%s\"", (x)), \
        void *:         LOG(#x ": %p", (x)), \
        void **:         LOG(#x ": %p", (x)) \
    )

#endif
