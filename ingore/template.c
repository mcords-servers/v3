#include "kit.h"

static void func(ptr ptr) {

}

__attribute__((constructor))
static void start() {
    LOG("Module %s loaded",FILENAME);
    on_event(EVENT, func);
}