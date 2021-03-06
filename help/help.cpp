﻿// Hash_C.cpp : 定义控制台应用程序的入口点。
//


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

	char* cExitProcess = "ExitProcess";
	int ret2 = Hash_GetDigest(cExitProcess);

	char* cws2_32 = "ws2_32.dll";
	int ret3 = Hash_GetDigest(cws2_32);

	char* cWSAStartup = "WSAStartup";
	int ret4 = Hash_GetDigest(cWSAStartup);

	char* cWSASocketA = "WSASocketA";
	int ret5 = Hash_GetDigest(cWSASocketA);

	char* cbind = "bind";
	int ret6 = Hash_GetDigest(cbind);

	char* clisten = "listen";
	int ret7 = Hash_GetDigest(clisten);

	char* caccept = "accept";
	int ret8 = Hash_GetDigest(caccept);

	char* cCreateProcessA = "CreateProcessA";
	int ret9 = Hash_GetDigest(cCreateProcessA);
	return 0;
}

