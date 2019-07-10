
int foo(int i){
	int arr[15];
	int j;
	for(j = 0; j < 15; j++) arr[j] = j;
	
	return arr[i];
}


int main(){
	foo(-2);
	

	return 0;
}
