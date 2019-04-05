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

void bar(){

	int val[5];
	int i = 0;
	
	for(i = 0; i < 5; i++){
		val[i] = i;
	}
	
	printf("ENTER: bar()\n");
	val[i] = 1234;
	printf("UNCHECKED !!!!!!!!!!\n");
}


int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: %s length\n", argv[0]);
        exit(1);
    }	
   
    size_t len = (size_t)atoi(argv[1]);

   	foo(len);

	bar();

    return 0;
}
