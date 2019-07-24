#pragma once
#include<Windows.h>
#include "../aplib.h"
#pragma comment(lib,"../aPlib.lib")
typedef struct _StubConf {
	DWORD oep;
	BYTE  encrypt_key;
	DWORD encrypt_rva;
	DWORD encrypt_size;
	DWORD compress_size;
}StubConf;
