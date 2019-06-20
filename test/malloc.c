#include <stdio.h>
#include <stdlib.h>
#include "lowfat_ds.h"


/*M_SIZE_G*/ size_t LOWFAT_GLOBAL_MS_7;
void* xmalloc (size_t n)
{

/*M_SIZE*/ LOWFAT_GLOBAL_MS_7 = n;
  void *p = malloc(LOWFAT_GLOBAL_MS_7);
  return p;
}

void bar(int i){
    int* ch = (int*) xmalloc(4*sizeof(int));
    ch[i] = 0;
}

int main(int argc, char **argv)
{
	int i = 4;
	
	bar(i);
	
    return 0;
}
