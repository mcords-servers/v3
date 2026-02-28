#include "kit.h"

// Some comments may be outdated
// because I kinda use this .c file in almost every single project of mine :D
// I'm really proud of this file :D
// It holds a lot of power

ptr **events; //If you see this: for the sake of your own sanity, leave before it's too late.

#define event_count 2 //Any non-zero value
#define event_func_count 2 //Same for this one
#define eof (void *)1 //Not the same, Don't touch this

void on_event(ptr event, ptr func) {
    if (!event) return;
    if (!events) {
        events = calloc(event_count+1, sizeof(ptr));
        events[0] = calloc(event_func_count+2, sizeof(ptr));
        events[0][0] = EVENT_LPS;
        events[0][event_func_count+1] = eof;
        events[event_count] = eof;
    }
    int i = 0;
    while (events[i]&&events[i]!=eof&&events[i][0]!=event) i += 1; //Fun fact it's 9:00 pm (seriously) what a coincidence
    ptr *funcs = NULL;
    if (!events[i]) {
        events[i] = calloc(event_func_count+2, sizeof(ptr));
        events[i][0] = event;
        events[i][1] = func;
        events[i][event_func_count+1] = eof;
        funcs = events[i];
        // LOG("Case: free slot found");
        // DEBUG(i);
    } else if (events[i]==eof) { //yea, from now on i will be leaving a lot of coments
        //and if you think this is none-sense: You are still reading it :D (so it does make sense)
        size_t old_size = i + 1;
        size_t new_size = i * 2 + 1;
        ptr **tmp = realloc(events, sizeof(ptr)*new_size);
        if (!tmp) return;
        events = tmp;
        size_t count = new_size - old_size;
        if (count > 0) memset(events + old_size, 0, count * sizeof(ptr));
        events[i] = calloc(event_func_count+2, sizeof(ptr));
        events[i][0] = event;
        events[i][1] = func;
        events[i][event_func_count+1] = eof;
        events[new_size-1] = eof;
        funcs = events[i];
        // LOG("Case: not enough space");
        // DEBUG(i);
    } else {
        // LOG("Case: same event found");
        funcs = events[i];
        // DEBUG(i);
    }

    int j = 1;
    while (funcs[j]&&funcs[j]!=eof&&funcs[j]!=func) j += 1;
    // DEBUG(j);
    // DEBUG(funcs[j]);
    if (funcs[j]==func) return;

    if (!funcs[j]) funcs[j] = func;
    else {
        size_t old_size = j + 1;
        size_t new_size = j * 2 - 1;
        ptr *tmp = realloc(funcs, sizeof(ptr)*new_size);
        if (!tmp) return;
        funcs = tmp;
        events[i] = funcs;
        size_t count = new_size - old_size;
        if (count > 0) memset(funcs + old_size, 0, count * sizeof(ptr));
        funcs[j] = func;
        funcs[new_size-1] = eof;
    }
}

void call_event(ptr event, ptr ptr) {
    if (!events||!event) return;
    int i = 0;
    while (events[i]!=eof) {
        if (events[i]&&events[i][0]==event) break;
        i += 1;
    }
    //Another fun fact it's 9:47 pm (day is +12 (12 days since previous comment))
    //Oh wait I must finish the on_event function first
    if (events[i]==eof) return;
    if (events[i][0]!=event) return;
    int j = 0;
    void (*func)(void *);
    // DEBUG(events[i]);
    while (events[i][++j]!=eof) {
        // DEBUG(j);
        if (!events[i][j]) continue;
        func = events[i][j];
        func(ptr);
    }
}

__attribute__((destructor))
static void func(void) {
    // if (events) { //I used this for debugging -_-
    //     puts("[");
    //     for (int i = 0;events[i]!=eof;i++) {
    //         if (!events[i]) {
    //             puts(" []");
    //             continue;
    //         }
    //         putc(' ',stdout);
    //         putc('[',stdout);
    //         for (int j = 0;events[i][j]!=eof;j++) printf("%p, ",events[i][j]);
    //         putc(']',stdout);
    //         putc('\n',stdout);
    //     }
    //     puts("]");
    // }
    call_event(EVENT_FRE, NULL);
    if (events) {
        for (int i = 0;events[i]!=eof;i++) {
            if (events[i]) free(events[i]);
        }
        free(events);
        events = NULL;
    }
}
