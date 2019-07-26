#pragma once
#include<Windows.h>
#include "../syub/stub.h"
#include "../aplib.h"
#pragma comment(lib,"../aPlib.lib")

typedef struct _StubInfo {
	PIMAGE_NT_HEADERS Dll_pNT;
	char* Dll_Buff;				// dll加载到内存的首地址(加载基址)
	DWORD Text_Size;			// 代码段的大小
	char* Text_Buff;			// 代码段的开始地址
	DWORD  Start_Offset;	// start导出函数在代码段的段内偏移
	StubConf* g_Conf;		// dll导出的全局变量的地址
}StubInfo;

typedef struct _Reloc {
	char* Reloc_Address;	// 重定位表所在首地址
	DWORD Reloc_Size;		//  重定位表大小

}Reloc,*PReloc;

class MySell{
public:
	MySell(const char* FilePath);
	 
	~MySell();

	//文件数据缓存
	char* m_pFile;
	int m_Size;

	//获取DOS头
	PIMAGE_DOS_HEADER m_pDos=nullptr;

	//保存NT头
	PIMAGE_NT_HEADERS m_pNT= nullptr;

	// 包含所有新区段的数据
	StubInfo m_StubInfo;

	// 保存 压缩段的文件首地址
	unsigned char* m_Text = NULL;

private:

	// 传入大小 对齐粒度
	DWORD Alignment(DWORD Size,DWORD Grain_Size);
	
	// 查找原程序最后一个区段
	PIMAGE_SECTION_HEADER Last_Section();

	//根据区段名称查找区段
	PIMAGE_SECTION_HEADER Scn_by_name(char* buff, const char* section_name);

	// 初始化重定位数据 获取dll中重定位的数据
	Reloc Init_Reloc();

public:
	// 1.判断是否是PE文件
	bool IsPE();

	//2. 获取新区段的信息
	void GetDllInfo();

	//3.添加新区段
	void Add_Section();

	// 4.对代码段进行加密
	void Encryption_Text();

	// 5.对代码段进行压缩
	void Compress_Text();

	// 6.修改其它信息
	void Alter_Other();

	// 7.移动修复重定位
	void Alter_Reloc();

	// 8.加密IAT
	void Hide_IAT();

	// 保存文件
	void SaveFile();

};