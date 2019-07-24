#include"stub.h"

#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")
#include "../aplib.h"
#pragma comment(lib,"../aplib.lib")

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
		DEFAPI("kernel32.dll", ExitProcess);
		DEFAPI("kernel32.dll", VirtualProtect);
		DEFAPI("kernel32.dll", VirtualAlloc);
		DEFAPI("kernel32.dll", VirtualFree);

		//获取代码首地址
		 char* Text = ( char*)(g_conf.encrypt_rva + GetBaseAddress());
		
		// 修改内存分页属性为可读可写
		DWORD old;
		My_VirtualProtect(Text, g_conf.encrypt_size, PAGE_READWRITE, &old);

		//获取被压缩的大小
		size_t Text_Size = g_conf.compress_size;

		// 计算原始大小
		size_t Orig_Size = aPsafe_get_orig_size(Text);//求得原数据的大小

		// 申请内存空间保存解密后的数据
		//char* data=NULL;
		LPVOID Data=My_VirtualAlloc(0, Orig_Size, 0x1000|0x2000, 0x4);

		g_conf.compress_size = aPsafe_depack(
			Text,     //被压缩的数据
			Text_Size,//被压缩后的大小
			Data,     //接收解压缩的数据
			Orig_Size       //原来的大小
		);

		// 把解密后的数据拷贝到原地址
		_asm{
			pushad
			mov esi, Data
			mov edi, Text
			mov ecx, g_conf.compress_size
			cld
			repe movsb
			popad

		}

		My_VirtualFree(Data, Orig_Size,2);
		// 恢复内存分页属性
		My_VirtualProtect(Text, g_conf.encrypt_size, old, &old);

		if (g_conf.compress_size != Orig_Size) {
			My_MessageBoxA(0,"解压缩失败!","错误",0);
			My_ExitProcess(0);
		}else{
			My_MessageBoxA(0, "解压缩成功!", "成功", 0);
		}
		
	}

	_declspec(dllexport)
		void _declspec(naked) start() {

		// 初始化两个重要函数的地址
		getApis();

		// 解压缩
		DeCompress();

		// 解密
		Decode();
		
		g_conf.oep+= GetBaseAddress();
		_asm jmp g_conf.oep;
	}


}
