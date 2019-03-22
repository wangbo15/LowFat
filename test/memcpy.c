#include<stdio.h>
#include<string.h>

#define PASS_NAME_SIZE 7
void passname (char name[PASS_NAME_SIZE])
{
    memcpy (name, "random", PASS_NAME_SIZE);
}

void cp_int(int* src, int* tar){
	memcpy(src, tar, sizeof(int));
}

void overlap(char* src){
	memcpy(src, src + 3, 4);
}

int main(){
	char pass_string[PASS_NAME_SIZE];
	
	fprintf(stderr, "pass_string: %p\n", pass_string);
	
	passname (pass_string);
	
	printf("RES: %s\n", pass_string);
	
	
	overlap(pass_string);
	
	printf("RES: %s\n", pass_string);
	
	int src[1];
	int tar[2] = {1, 2};
	
	cp_int(src, tar);
	
	printf("RES: %d\n", src[0]);
		
	return 0;
}
