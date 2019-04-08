#include<stdio.h>
/*
struct AAA{
	char pad[2];
	char global[6];
};

struct AAA aaa = {
	{0, 0},
	{1,2,3,4,5,6}
};
*/

char global[10] = {'1', '2', '3'};


void bar(char *buf){

	//buf[2] = '4';

	//printf("%s\n", buf);
	
	buf[10] = '4';
}

int main(){

	bar(global);
		
	return 0;
}
