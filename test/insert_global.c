#include <stdio.h>
#include <stdlib.h>
#include "lowfat_ds.h"

//int g_time = 0;



int main(int argc, char **argv)
{

    if (argc != 2)
    {
        fprintf(stderr, "usage: %s length\n", argv[0]);
        exit(1);
    }
    size_t size = (size_t)atoi(argv[1]);
    char *buf = (char *)malloc(size);
    printf("malloc(%zu) = %p\n", size, buf);
    printf("Enter a string: ");
    fflush(stdout);
    int i;
    for (i = 0; (buf[i] = getchar()) != '\n'; i++)
        ;
    buf[i] = '\0';
    printf("String = \"%s\"\n", buf);

    return 0;
}

/*
void foo(unsigned long a, unsigned long b){
	
	unsigned long size = a + b;
	
	size++;	

	char *buf = (char *)malloc(size);

	//unsigned long x = 123;
	//buf = (char *)malloc(x);
}*/


