#pragma once
#include<Windows.h>
typedef struct _StubConf {
	DWORD oep;
	BYTE  encrypt_key;
	DWORD encrypt_rva;
	DWORD encrypt_size;
}StubConf;
