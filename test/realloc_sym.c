#include<stdio.h>
#include<string.h>
#include<stdlib.h>


size_t LOWFAT_GLOBAL_MS_larger_1;

void larger(){
	printf("LARGER:\n");
	char* ori = (char*) malloc (4);
	memcpy(ori, "0.0", 4);
	printf("ori: %s\n", ori);
	
	ori = (char*) realloc(ori, ({LOWFAT_GLOBAL_MS_larger_1 = 12; LOWFAT_GLOBAL_MS_larger_1;}));
	
	// overflow
	ori[12] = '\0';
	
	
	printf("ori: %s\n", ori);
}

int main(){

	larger();
		
	return 0;
}
