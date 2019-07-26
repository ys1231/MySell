#pragma once
#include<Windows.h>
typedef struct _StubConf {
	DWORD oep;					//原始OEP
	BYTE  encrypt_key;			//解密key
	DWORD encrypt_rva;			//解密段RVA
	DWORD encrypt_size;			//解密大小
	DWORD compress_size;		//压缩后的大小
	char str_key[5];			//用户设置的密码
	DWORD OldRelocAddress;		//原重定位表RVA
	DWORD OldRelocSize;			//原重定位表大小

	DWORD Import_Rva;

}StubConf;
