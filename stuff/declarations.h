#ifndef D_H
#define D_H

#include "kit.h"

void on_event(ptr event, ptr func);
void call_event(ptr event, ptr ptr);

#define EVENT (void *)0
#define EVENT_LPS (void *)1
#define EVENT_FRE (void *)2

#endif
