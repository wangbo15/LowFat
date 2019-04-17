#include<stdlib.h>

int SATD ()
{
  int k, satd = 0, m[16], dd, d[16];
  for (dd=d[k=0]; k<16; dd= d[++k]) {
    satd += (dd < 0 ? -dd : dd);
  }
  
  return satd;
}


int main(){
  int res = SATD();
  return 0;
}
