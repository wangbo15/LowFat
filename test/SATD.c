

int SATD (void)
{
  int d[16];

  int satd = 0, dd, k;
  for (dd=d[k=0]; k<16; dd=d[++k]) {
    satd += (dd < 0 ? -dd : dd);
  }
  return satd;
}

int main(){
	
  int res = SATD();
  return 0;
}
