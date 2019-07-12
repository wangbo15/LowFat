#include<stdio.h>
#include<string.h>
#include<stdlib.h>


size_t LOWFAT_GLOBAL_MS_foo_1;

void foo(){
	char* ori = (char*) calloc (1, ({LOWFAT_GLOBAL_MS_foo_1 = 3 * 4; LOWFAT_GLOBAL_MS_foo_1;}));
	// overflow
	ori[12] = '\0';
	
	printf("ori: %s\n", ori);
}

int main(){
	foo();
	return 0;
}
