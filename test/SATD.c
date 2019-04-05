#include<stdlib.h>

int d[16] = {1,2, 3, 4};
int * d_LOWFAT_GLOBAL_BASE = (d + 16);

//int G;
//int G_base = ((size_t)&G + 16 - sizeof(G));

char * const_str = "";
char * const_str_base = (&"" + 15);

int SATD ()
{
  int satd = 0, dd, k;
  for (dd=d[k=0]; k<16; dd= d[++k]) {
    satd += (dd < 0 ? -dd : dd);
  }
  
  return satd;
}


void foo(){
	char * s = const_str;
	s++;
	*s = ' ';
	
}

void bar(){

	printf("%p %p\n", d, d_LOWFAT_GLOBAL_BASE);
	
	//d_base[1];
	
}

int main(){
	
  int res = SATD();
  
  bar();
  
  return 0;
}
