/*
 * Test program for #2 (https://github.com/GJDuck/LowFat/issues/2)
 *
 * Usage:
 *  $ clang -o issue_2 -O2 -fsanitize=lowfat issue_2.c
 *  $ ./issue_2
 * The program should abort with a OOB-read error.
 */

#include <stdio.h>
#include <stdlib.h>


void foo(size_t len){
	char arr[len];

    int i;
    for (i = 0; (arr[i] = getchar()) != '\n'; i++)
        ;
    arr[i] = '\0';
    printf("String = \"%s\"\n", arr);

}


/*
void bar(size_t len){
	int val[len];

	
	int i = 0;
	
	for(i = 0; i < len; i++){
		val[i] = i;
	}
	//i = len + 1;
	
	printf("len: %zu, size: %zu, i : %d\n", len, sizeof(val), i);

	val[i] = 1234;
}*/


int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: %s length\n", argv[0]);
        exit(1);
    }	
   
    size_t len = (size_t)atoi(argv[1]);

   	foo(len);

	//bar(len);

    return 0;
}
