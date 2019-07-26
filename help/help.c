// Hash_C.cpp : 定义控制台应用程序的入口点。
//

#include<stdio.h>

int Hash_GetDigest(char* strFunName)
{
	unsigned int nDigest = 0;
	while (*strFunName)
	{
		nDigest = (nDigest << 25) | (nDigest >> 7);
		nDigest = nDigest + *strFunName;
		strFunName++;
	}
	return nDigest;
}

int main()
{
	char* cLoadLibraryExA = "LoadLibraryExA";
	int ret1 = Hash_GetDigest(cLoadLibraryExA);
	printf("%d\n",ret1);
	char* cExitProcess = "ExitProcess";
	int ret2 = Hash_GetDigest(cExitProcess);
	printf("%d\n", ret2);
	char* cws2_32 = "ws2_32.dll";
	int ret3 = Hash_GetDigest(cws2_32);
	printf("%d\n", ret3);
	char* cWSAStartup = "WSAStartup";
	int ret4 = Hash_GetDigest(cWSAStartup);
	printf("%d\n", ret4);
	char* cWSASocketA = "WSASocketA";
	int ret5 = Hash_GetDigest(cWSASocketA);
	printf("%d\n", ret5);
	char* cbind = "bind";
	int ret6 = Hash_GetDigest(cbind);
	printf("%d\n", ret6);
	char* clisten = "listen";
	int ret7 = Hash_GetDigest(clisten);
	printf("%d\n", ret7);
	char* caccept = "accept";
	int ret8 = Hash_GetDigest(caccept);
	printf("%d\n", ret8);
	char* cCreateProcessA = "CreateProcessA";
	int ret9 = Hash_GetDigest(cCreateProcessA);
	printf("%d\n", ret9);
	//char* cCreateProcessA = "CreateProcessA";
	int ret91 = Hash_GetDigest(cCreateProcessA);
	printf("%d\n", ret91);
	return 0;
}

