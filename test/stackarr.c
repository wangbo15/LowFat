
void foo(){
	char tmp[100] = {0};
}

void bar(){
	char tmp[100];
	char *p = tmp;
	
	int i;
	for(i = 0; i < 100; i++){
		p[i] = 0;
	}
}

int main(){
	foo();
	return 0;
}
