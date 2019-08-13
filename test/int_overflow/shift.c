#include<stdio.h>
#include<limits.h>

int shift_left(int a, int b){
	return a << b;
}

int shift_right(int a, int b){
	return a >> b;
}


int main(){
	int a = shift_left(-1, 29);
	
	int b = shift_right(-1, 3);
	
	printf("%d, %d\n", a, b);

	return 0;
}
