//
// Created by nightwish on 19-2-26.
//

#include <map>

#include "stl_interface.h"

typedef std::map<size_t, size_t> Map;

#ifdef __cplusplus
extern "C" {
#endif

/** STL MAP INTERFACE IMPLEMENTATIONS **/
any_t map_create() {
    return reinterpret_cast<any_t > (new Map);
}

void map_put(any_t map, size_t k, size_t v) {
    Map* m = reinterpret_cast<Map*> (map);
    m->insert(std::pair<size_t, size_t>(k, v));
}

size_t map_get(any_t map, size_t k) {
    Map* m = reinterpret_cast<Map*> (map);
    if(m->count(k) == 0){
        return 0x0;
    }else{
        return (size_t) m->find(k)->second;
    }
}

void map_remove(any_t map, size_t k){
    Map* m = reinterpret_cast<Map*> (map);
    if(m->count(k) > 0){
        m->erase(k);
    }
}

int map_size(any_t map){
    Map* m = reinterpret_cast<Map*> (map);
    return m->size();
}


#ifdef __cplusplus
} // extern "C"
#endif