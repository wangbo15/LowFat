//
// Created by nightwish on 19-2-15.
// Containing lowfat data structures for symbolize
//

#ifndef LLVM_LOWFAT_DS_H
#define LLVM_LOWFAT_DS_H

#include <stdlib.h>
#include <stdint.h>

typedef struct malloc_linked_list_head
{
    // malloc times
    int time;

    // variable name
    char* name;

    // the pointer of the globalized size, for symbolic
    size_t* glo_addr;

    // record the real allocated base address
    void* real_base;

} MALLOC_LIST_HEAD;

typedef struct lowfat_source_location
{
    char *Filename;
    u_int32_t Line;
    u_int32_t Column;
} LOWFAT_SRC_LOC;

typedef struct lowfat_type_descriptor
{
    u_int16_t TypeKind;
    u_int16_t TypeInfo;
    char* TypeName;
} LOWFAT_TYPE_DESC;

typedef struct lowfat_overflow_data
{
    LOWFAT_SRC_LOC Loc;
    LOWFAT_TYPE_DESC* Type;
} LOWFAT_OVERFLOW_DATA;

typedef struct lowfat_overshift_data
{
    LOWFAT_SRC_LOC Loc;
    LOWFAT_TYPE_DESC* LHSType;
    LOWFAT_TYPE_DESC* RHSType;
} LOWFAT_OVERSHIFT_DATA;

#endif
