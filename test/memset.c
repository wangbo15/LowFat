#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(){
	char* pass_string = (char*)malloc(16);
	
	fprintf(stderr, "pass_string: %p\n", pass_string);
	
	memset(pass_string, 'a', 16);
	
	pass_string[15] = '\0';
	printf("%s\n", pass_string);
		
	return 0;
}
