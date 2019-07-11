#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LARGE_LENGTH 4294967294

size_t LOWFAT_GLOBAL_MS_getLongStr;
char* getLongStr(){
    char *str = (char *) malloc (({LOWFAT_GLOBAL_MS_getLongStr = LARGE_LENGTH; LOWFAT_GLOBAL_MS_getLongStr;}));
    if(str == NULL){
        printf("Large string allocation error\n");
        exit(1);
    }
    fprintf(stderr, "Malloc: %zu\n", LOWFAT_GLOBAL_MS_getLongStr);
    memset(str, 'A', LARGE_LENGTH-1);
    str[LARGE_LENGTH-1] = 0;
    return str;
}

size_t LOWFAT_GLOBAL_MS_getHelfLongStr;
char* getHelfLongStr(){
    char *str = (char *) malloc (({LOWFAT_GLOBAL_MS_getHelfLongStr = (LARGE_LENGTH /2); LOWFAT_GLOBAL_MS_getHelfLongStr;}));
    if(str == NULL){
        printf("Large string allocation error\n");
        exit(1);
    }
    fprintf(stderr, "Malloc: %zu\n", LOWFAT_GLOBAL_MS_getHelfLongStr);
    memset(str, 'A', LARGE_LENGTH-1);
    str[LARGE_LENGTH-1] = 0;
    return str;
}

int main(){
	char* str1 = getLongStr();
	//char* str2 = getHelfLongStr();
	//char* str3 = getHelfLongStr();
	return 0;
}
