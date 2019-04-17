#include<stdio.h>

static char const *col_sep_string = "";

static void print_sep_string ()
{
  char const *s = col_sep_string;
  
  
  printf("%d\n", strlen(s));
  
  
  putchar (*s++);
  if (*s == ' '){
	s++;
  }
  
  printf("%d\n", strlen(s));
}


int main(){

	print_sep_string();
		
	return 0;
}
