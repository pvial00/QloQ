#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qloq.h"

int main() {
    struct qloq_ctx ctx;
    int psize = 1536;
    keygen(&ctx, psize);
    return 0;
}

