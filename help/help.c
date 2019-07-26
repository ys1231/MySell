// Hash_C.cpp : 定义控制台应用程序的入口点。
//

#include <stdio.h>
#include<Windows.h>
void rev(char*src,char*dec)
{
	int j = 3;
	for(int i=0;i<4;i++)
	{
		dec[j] = ((DWORD*)src+i);
		j--;
	}

}
int main()
{
	DWORD a = 0x12345678;
	
	char* str = &a;

	


	return 0;
}

