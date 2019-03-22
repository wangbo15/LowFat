#include<stdio.h>
#include<string.h>
#include<stdlib.h>

void same(){
	printf("SAME:\n");
	char* ori = (char*) malloc (4);
	memcpy(ori, "0.9", 4);
	printf("ori: %s\n", ori);
	
	ori = (char*) realloc(ori, 4);
	printf("ori: %s\n", ori);
}

void smaller(){
	printf("SMALLER:\n");
	char* ori = (char*) malloc (12);
	memcpy(ori, "0.9", 4);
	printf("ori: %s\n", ori);
	
	ori = (char*) realloc(ori, 4);
	printf("ori: %s\n", ori);
}

void larger(){
	printf("LARGER:\n");
	char* ori = (char*) malloc (4);
	memcpy(ori, "0.0", 4);
	printf("ori: %s\n", ori);
	
	ori = (char*) realloc(ori, 12);
	ori[3] = '9';
	ori[4] = '8';
	ori[5] = '7';
	ori[6] = '6';
	ori[7] = '\0';
	
	printf("ori: %s\n", ori);
}

int main(){
	same();
	smaller();
	larger();
		
	return 0;
}
