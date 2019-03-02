//
// Created by nightwish on 19-2-26.
//
#ifndef LLVM_STL_INTERFACE_H
#define LLVM_STL_INTERFACE_H

#include <stddef.h>

typedef void *any_t;

#ifndef __cplusplus

/** FOR STL MAP **/
any_t map_create();

void map_put(any_t map, size_t key, size_t value);

size_t map_get(any_t map, size_t k);

void map_remove(any_t map, size_t k);

int map_size(any_t map);

#endif


#endif //LLVM_STL_INTERFACE_H
