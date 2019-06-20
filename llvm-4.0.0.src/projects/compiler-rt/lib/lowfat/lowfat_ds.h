//
// Created by nightwish on 19-2-15.
// Containing lowfat data structures for symbolize
//

#ifndef LLVM_LOWFAT_DS_H
#define LLVM_LOWFAT_DS_H

#include <stdlib.h>

typedef struct malloc_linked_list_head{
    // malloc times
    int time;

    // variable name
    char* name;

    // the pointer of the globalized size, for symbolic
    size_t* glo_addr;
} MALLOC_LIST_HEAD;


#endif
