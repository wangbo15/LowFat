//
// Created by nightwish on 19-2-15.
// Containing lowfat data structures for symbolize
//

#ifndef LLVM_LOWFAT_DS_H
#define LLVM_LOWFAT_DS_H


typedef struct malloc_linked_list_head{
    // malloc times
    int time;

    // variable name
    char* name;

    // malloc list
    struct malloc_linked_list *next;

} MALLOC_LIST_HEAD;


typedef struct malloc_linked_list{
    // malloc size
    int size;

    // the next node
    struct malloc_linked_list *next;
} MALLOC_LIST;


#endif
