#include <stdio.h>
#include <stdlib.h>
#include "lowfat_ds.h"


void* xmalloc (size_t n)
{
  void *p = malloc (n);
  return p;
}

int main(int argc, char **argv)
{
    char* ch = xmalloc(4);
	
	
    return 0;
}
