#include<stdio.h>
#include<limits.h>

int signed_minus(int a, int b){
	return a - b;
}

unsigned int unsigned_minus(unsigned int a, unsigned int b){
	return a - b;
}

int signed_add(int a, int b){
	return a + b;
}

unsigned int unsigned_add(unsigned int a, unsigned int b){
	return a + b;
}

int main(){

	unsigned int u = unsigned_add(1, INT_MAX);
	
	printf("%u\n", u);
	
	int s = signed_add(1, INT_MAX); //signed_minus(INT_MIN, 1);
	
	printf("%d\n", s);
	
	return 0;
}
