#include"stub.h"
#
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")

HMODULE g_hkernel32;

typedef void* (WINAPI* FnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
FnGetProcAddress pfnGetProcAddress;

typedef HMODULE(WINAPI* FnLoadLibraryA)(const char*);
FnLoadLibraryA pfnLoadLibraryA;

#define DEFAPI(modName,funType) \
	decltype(funType)* My_##funType = (decltype(funType)*)\
pfnGetProcAddress(pfnLoadLibraryA(modName), #funType);

// 获取当前EIP
DWORD Getjizhi()
{
	_asm {
		CALL EIPP
		EIPP :
		POP EAX
	}
}
DWORD GetBaseAddress()
{
	DWORD aaa = Getjizhi();

	return aaa & 0xFFFF0000;
}

extern "C" {

	// 导出数据 给加壳器 填写 主要是解密 和OEP
	_declspec(dllexport)StubConf g_conf;

	// 获取 Kernel32基址
	HMODULE GetKernel32()
	{
		_asm
		{
			MOV EAX, DWORD PTR FS : [0x30]
			MOV EAX, DWORD PTR DS : [EAX + 0xC]
			MOV EAX, DWORD PTR DS : [EAX + 0xC]
			MOV EAX, DWORD PTR DS : [EAX]
			MOV EAX, DWORD PTR DS : [EAX]
			MOV EAX, DWORD PTR DS : [EAX + 0x18]
		}
	}

	//获取GetProcAddress 函数地址
	void* indexGetProcAddress()
	{
		// 1. 获取Kernel32基址
		HMODULE hKernel32 = GetKernel32();

		IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)hKernel32;
		IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)
			(pDos->e_lfanew + (DWORD)pDos);

		IMAGE_EXPORT_DIRECTORY* pExp = (IMAGE_EXPORT_DIRECTORY*)
			(pNt->OptionalHeader.DataDirectory[0].VirtualAddress + (DWORD)pDos);

		DWORD* pEnt = (DWORD*)(pExp->AddressOfNames + (char*)pDos);
		DWORD* pEat = (DWORD*)(pExp->AddressOfFunctions + (char*)pDos);
		WORD* pEot = (WORD*)(pExp->AddressOfNameOrdinals + (char*)pDos);

		for (int i = 0; i < pExp->NumberOfFunctions; ++i)
		{
			// 遍历名称表找到GetP rocA ddre ss
			char* name = pEnt[i] + (char*)pDos;
			if (*(DWORD*)name == 'PteG'
				&& *(DWORD*)(name + 4) == 'Acor'
				&& *(DWORD*)(name + 8) == 'erdd'
				&& *(WORD*)(name + 12) == 'ss')
			{
				DWORD addrIndex = pEot[i];
				return pEat[addrIndex] + (char*)pDos;
			}

		}
		return NULL;
	}
	// 获取API的两个关键函数
	void getApis()
	{
		g_hkernel32 = GetKernel32();
		pfnGetProcAddress = (FnGetProcAddress)
			(indexGetProcAddress());
		pfnLoadLibraryA = (FnLoadLibraryA)
			(pfnGetProcAddress(g_hkernel32, "LoadLibraryA"));
	}

	// 解密函数
	void Decode()
	{
		DEFAPI("kernel32.dll", VirtualProtect);

		unsigned char* text_buff = (unsigned char*)( g_conf.encrypt_rva+ GetBaseAddress());
		// 修改内存分页属性为可读可写
		DWORD old;
		My_VirtualProtect(text_buff, g_conf.encrypt_size, PAGE_READWRITE, &old);
		for (int i = 0; i < g_conf.encrypt_size; ++i) {
			text_buff[i] ^= g_conf.encrypt_key;
		}
		// 恢复内存分页属性
		My_VirtualProtect(text_buff, g_conf.encrypt_size, old, &old);
	}

	// 解压缩函数
	void DeCompress()
	{
		DEFAPI("user32.dll", MessageBoxA);

		unsigned char* compressed = (unsigned char*)(g_conf.encrypt_rva + GetBaseAddress());
		size_t compressed_size = g_conf.compress_size;
		size_t orig_size = aPsafe_get_orig_size(compressed);//求得原数据的大小

		/* allocate memory for decompressed data */
		char* data = (char*)malloc(orig_size);

		/* decompress compressed[] to data[] */
		g_conf.compress_size = aPsafe_depack(
			compressed,     //被压缩的数据
			compressed_size,//被压缩后的大小
			data,           //接收解压缩的数据
			orig_size       //原来的大小
		);

		/* check decompressed length */
		if (g_conf.compress_size != orig_size) {
			My_MessageBoxA(0,"错误","解压缩失败!",0);
			DEFAPI("kernel32.dll", ExitProcess);
			My_ExitProcess(0);
		}
		else {
			//My_MessageBoxA(0,"""%s\nDecompressed %u bytes\n", data, g_conf.compress_size);
			DEFAPI()
		}
	}

	_declspec(dllexport)
		void _declspec(naked) start() {

		getApis();

		Decode();

		g_conf.oep+= GetBaseAddress();
		_asm jmp g_conf.oep;
	}


}
