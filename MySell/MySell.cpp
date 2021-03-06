﻿#include"MySell.h"
#include <cstdio>
#include <cstdlib>
#include <ctime>

MySell::MySell(const char* FilePath)
{
	// 1. 打开一个文件
	FILE* file = fopen(FilePath, "rb");

	// 2. 检查文件是否打开失败
	if(!file)
	{
		printf("文件打开失败\n");
		return;
	}
	// 2. 读取文件内容
	fseek(file, 0, SEEK_END);
	m_Size = ftell(file);
	// 重新定位指向文件开头的文件指针
	rewind(file);
	m_pFile= (char*)malloc(m_Size);
	fread(m_pFile, 1, m_Size, file);
	fclose(file);

	// 获取NT头
	m_pDos = (PIMAGE_DOS_HEADER)m_pFile;
	m_pNT = (PIMAGE_NT_HEADERS)(m_pDos->e_lfanew + m_pFile);

	//判断是否是PE文件
	if(!IsPE())
	{
		printf("不是有效的PE文件\n");
		return;
	}

	GetDllInfo();

	// 初始化随机函数
	srand((unsigned)time(NULL));

	return;
}

MySell::~MySell()
{
}

DWORD MySell::Alignment(DWORD Size, DWORD Grain_Size)
{
	return Size% Grain_Size==0? Size:(Size/ Grain_Size+1)* Grain_Size;
}

bool MySell::IsPE()
{
	if (m_pDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}
	if (m_pNT->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}
	return TRUE;
}

PIMAGE_SECTION_HEADER MySell::Last_Section()
{
	// 1.获取第一个区段首地址
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(m_pNT);

	// 2.找到原程序最后一个区段
	pSection += (m_pNT->FileHeader.NumberOfSections - 2);

	return  pSection;
}

PIMAGE_SECTION_HEADER MySell::Scn_by_name(char* buff, const char* section_name)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buff;
	PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + buff);

	IMAGE_SECTION_HEADER* scn_hdr =
		IMAGE_FIRST_SECTION(pNT);
	DWORD scn_cnt =pNT->FileHeader.NumberOfSections;
	char scn_name[10];
	for (DWORD i = 0; i < scn_cnt; ++i) {
		memset(scn_name, 0, sizeof(scn_name));
		memcpy(scn_name, scn_hdr[i].Name, 8);
		if (strcmp(scn_name, section_name) == 0) {
			return scn_hdr + i;
		}
	}
	return NULL;
}

Reloc MySell::Init_Reloc()
{
	// 1.获取新区段首地址
	PIMAGE_SECTION_HEADER p_Sec = Last_Section() + 1;

	// 获取 dll重定位表的VA 地址 和大小
	Reloc rel;
	rel.Reloc_Address= m_StubInfo.Dll_pNT->OptionalHeader.DataDirectory[5].VirtualAddress + m_StubInfo.Dll_Buff;
	rel.Reloc_Size =m_StubInfo.Dll_pNT->OptionalHeader.DataDirectory[5].Size;

	DWORD old;
	VirtualProtect((LPVOID)rel.Reloc_Address, rel.Reloc_Size, PAGE_READWRITE, &old);

	// 重定位表首地址
	PIMAGE_BASE_RELOCATION pRel = (PIMAGE_BASE_RELOCATION)rel.Reloc_Address;
	
	// text段的
	DWORD text_rva = Scn_by_name(m_StubInfo.Dll_Buff, ".text")->VirtualAddress;

	// 修复重定位数据
	while (pRel->SizeOfBlock)
	{
		// 重定位首地址RVA + 新区段RVA - 原区段的RVA
		pRel->VirtualAddress = pRel->VirtualAddress+ p_Sec->VirtualAddress - text_rva;
		pRel = (PIMAGE_BASE_RELOCATION)((DWORD)pRel+ pRel->SizeOfBlock);
		
	}
	VirtualProtect((LPVOID)rel.Reloc_Address, rel.Reloc_Size, old, &old);

	// 获取区段的VA 和实际大小
	rel.Reloc_Address = (char*)(Scn_by_name(m_StubInfo.Dll_Buff, ".reloc")->VirtualAddress+m_StubInfo.Dll_Buff);
	rel.Reloc_Size = Scn_by_name(m_StubInfo.Dll_Buff, ".reloc")->Misc.VirtualSize;

	return rel;

}

void MySell::GetDllInfo()
{
	// 开始加载ＤＬＬ
	HMODULE dll = LoadLibraryEx(L"syub.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!dll) {
		printf("stub.dll加载失败\n");
		return;
	}
	//获取PE头
	m_StubInfo.Dll_Buff = (char*)dll;

	// 获取DLL NT头
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_StubInfo.Dll_Buff;
	m_StubInfo.Dll_pNT = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_StubInfo.Dll_Buff);

	// 获取代码段
	PIMAGE_SECTION_HEADER Text_Sec_Hdr;
	
	// 获取代码段首地址
	Text_Sec_Hdr = Scn_by_name(m_StubInfo.Dll_Buff, ".text");

	// 获取 代码段的开始位置
	m_StubInfo.Text_Buff =Text_Sec_Hdr->VirtualAddress+ (char*)dll;

	// 获取代码段的大小
	m_StubInfo.Text_Size = Text_Sec_Hdr->Misc.VirtualSize;

	// 获取导出函数的段内偏移
	char* start = (char*)GetProcAddress(dll, "start");
	DWORD rva_start = (LONG_PTR)start - (LONG_PTR)dll;
	DWORD offset = rva_start - Text_Sec_Hdr->VirtualAddress;
	m_StubInfo.Start_Offset = offset;

	// 获取导出变量
	m_StubInfo.g_Conf = (StubConf*)GetProcAddress(dll, "g_conf");
	printf("获取壳数据完成!\n");
}

void MySell::Add_Section()
{
	// 1.修改区段个数
 	m_pNT->FileHeader.NumberOfSections++;

	// 2.修改区段名称
	PIMAGE_SECTION_HEADER pNewSec=Last_Section() + 1;
	memcpy(pNewSec->Name, ".Zj1231", 8);

	// 3.修改区段实际大小				//读取dll的获取的text段大小
	pNewSec->Misc.VirtualSize = m_StubInfo.Text_Size;

	// 4.修改文件对齐大小
	pNewSec->SizeOfRawData = Alignment(m_StubInfo.Text_Size, m_pNT->OptionalHeader.FileAlignment);

	// 5.修改文件偏移
	pNewSec->PointerToRawData = Alignment(m_Size, m_pNT->OptionalHeader.FileAlignment);

	// 6.修改内存偏移
	pNewSec->VirtualAddress = Last_Section()->VirtualAddress + Alignment(Last_Section()->SizeOfRawData, m_pNT->OptionalHeader.SectionAlignment);

	// 7.修改区段属性
	pNewSec->Characteristics = 0xE00000E0;

	// 8.修改映像大小
	m_pNT->OptionalHeader.SizeOfImage = pNewSec->VirtualAddress + m_StubInfo.Text_Size;

	// 9,修改文件数据大小 

	// 1.先获取修改后的文件大小
	int NewSize = pNewSec->PointerToRawData + pNewSec->SizeOfRawData;

	// 2.扩大对空间 保证有那么大的文件
	m_pFile = (char*)realloc(m_pFile, NewSize);
	// 获取NT头
	m_pDos = (PIMAGE_DOS_HEADER)m_pFile;
	m_pNT = (PIMAGE_NT_HEADERS)(m_pDos->e_lfanew + m_pFile);

	// 修改原文件保存的大小
	m_Size = NewSize;

	printf("修改区段数据完成\n");
	return;
}


void MySell::Alter_Other()
{

	// 1.获取新区段首地址
	PIMAGE_SECTION_HEADER p_Sec = Last_Section() + 1;
	
	// 2.修改 OEP 
	m_StubInfo.g_Conf->oep= m_pNT->OptionalHeader.AddressOfEntryPoint;
	m_pNT->OptionalHeader.AddressOfEntryPoint = m_StubInfo.Start_Offset+p_Sec->VirtualAddress;

	// 3.修复重定位
	
	PIMAGE_BASE_RELOCATION pRel = (PIMAGE_BASE_RELOCATION)(m_StubInfo.Dll_pNT->OptionalHeader.DataDirectory[5].VirtualAddress + m_StubInfo.Dll_Buff);

	DWORD text_rva = Scn_by_name(m_StubInfo.Dll_Buff, ".text")->VirtualAddress;
	typedef struct
	{
		WORD offset : 12;
		WORD type : 4;
	}TypeOffset,*PTypeOffset;

		// 遍历出所有的重定位项
	while (pRel->SizeOfBlock)
	{
		
		PTypeOffset type_offset = (PTypeOffset)(pRel + 1);
		DWORD count = (pRel->SizeOfBlock - 8) / 2;
		for (DWORD i = 0; i < count; ++i) {
			if (type_offset[i].type == 3) {
				DWORD rel_item_rva = type_offset[i].offset + pRel->VirtualAddress;
				DWORD* rel_addr = (DWORD*)(rel_item_rva + m_StubInfo.Dll_Buff);
				//2. 重定位项 -= dll加载基址
				//3. 重定位项 -= dll的代码段的段首rva
				//4. 重定位项 += 新的加载基址
				//5. 重定位项 += 新的段首rva
				DWORD old;
				VirtualProtect(rel_addr, 4, PAGE_READWRITE, &old);
				*rel_addr -= (ULONG_PTR)m_StubInfo.Dll_Buff;
				*rel_addr -= text_rva;

				*rel_addr += m_pNT->OptionalHeader.ImageBase;
				*rel_addr += p_Sec->VirtualAddress;
			}
		}
		pRel = (IMAGE_BASE_RELOCATION*)
			((char*)pRel + pRel->SizeOfBlock);
	}

	// 4.去出支持随机基址的标志位
	//m_pNT->OptionalHeader.DllCharacteristics &= ~(0x40);

	// 5.将stub的代码段拷贝到新区段
	char*pNewSecText= p_Sec->PointerToRawData + m_pFile;

	// 设置程序密码
	printf("请输入壳密码(4位)\n:");
	scanf_s("%s",&m_StubInfo.g_Conf->str_key,5);

	// 先保存原来重定位表的RVA和Size
	m_StubInfo.g_Conf->OldRelocAddress = m_pNT->OptionalHeader.DataDirectory[5].VirtualAddress;
	m_StubInfo.g_Conf->OldRelocSize = m_pNT->OptionalHeader.DataDirectory[5].Size;

	memcpy(pNewSecText,m_StubInfo.Text_Buff, m_StubInfo.Text_Size);

	printf("修复壳代码重定位完成\n");
}

void MySell::Alter_Reloc()
{
	// 开始修复重定位
	Reloc rel= Init_Reloc();
	// 1.修改区段个数
	m_pNT->FileHeader.NumberOfSections++;

	// 2.修改区段名称
	PIMAGE_SECTION_HEADER pNewSec = Last_Section() + 1;
	memcpy(pNewSec->Name, ".Rreloc", 8);

	// 3.修改区段实际大小				//读取dll的获取的reloc段大小
	pNewSec->Misc.VirtualSize =rel.Reloc_Size;

	// 4.修改文件对齐大小
	pNewSec->SizeOfRawData = Alignment(rel.Reloc_Size, m_pNT->OptionalHeader.FileAlignment);

	// 5.修改文件偏移
	pNewSec->PointerToRawData = Alignment(m_Size, m_pNT->OptionalHeader.FileAlignment);

	// 6.修改内存偏移
	pNewSec->VirtualAddress = Last_Section()->VirtualAddress + Alignment(Last_Section()->SizeOfRawData, m_pNT->OptionalHeader.SectionAlignment);

	// 7.修改区段属性
	pNewSec->Characteristics = 0xE00000E0;

	// 8.修改映像大小
	m_pNT->OptionalHeader.SizeOfImage = pNewSec->VirtualAddress + rel.Reloc_Size;

	// 9,修改文件数据大小 

	// 1.先获取修改后的文件大小
	int NewSize = pNewSec->PointerToRawData + pNewSec->SizeOfRawData;

	// 2.扩大对空间 保证有那么大的文件
	m_pFile = (char*)realloc(m_pFile, NewSize);
	// 获取NT头
	m_pDos = (PIMAGE_DOS_HEADER)m_pFile;
	m_pNT = (PIMAGE_NT_HEADERS)(m_pDos->e_lfanew + m_pFile);

	// 修改原文件保存的大小
	m_Size = NewSize;

	// 把重定位的数据拷贝过来 
	char* pNewSecReloc = pNewSec->PointerToRawData + m_pFile;
	memcpy(pNewSecReloc, rel.Reloc_Address, rel.Reloc_Size);

	// 修改重定位表指向新区段 
	m_pNT->OptionalHeader.DataDirectory[5].VirtualAddress = pNewSec->VirtualAddress;
	m_pNT->OptionalHeader.DataDirectory[5].Size = rel.Reloc_Size;

	printf("修复重定位指向完成\n");
	return;

}

void MySell::Hide_IAT()
{
	m_StubInfo.g_Conf->Import_Rva = m_pNT->OptionalHeader.DataDirectory[1].VirtualAddress;
	m_StubInfo.g_Conf->Import_Size=m_pNT->OptionalHeader.DataDirectory[1].Size ;
	m_pNT->OptionalHeader.DataDirectory[1].Size = 0;
	m_pNT->OptionalHeader.DataDirectory[1].VirtualAddress = 0;
	m_pNT->OptionalHeader.DataDirectory[12].Size = 0;
	m_pNT->OptionalHeader.DataDirectory[12].VirtualAddress = 0;

}

void MySell::Encryption_Text()
{
	// 1.先保存密码 代码段起始位置 大小
	m_StubInfo.g_Conf->encrypt_key = rand() % 255;
	m_StubInfo.g_Conf->encrypt_rva = Scn_by_name(m_pFile, ".text")->VirtualAddress;
	m_StubInfo.g_Conf->encrypt_size = Scn_by_name(m_pFile, ".text")->Misc.VirtualSize;

	// 2.在文件偏移的位置开始加密 大小就是实际大小
	unsigned char* Sec_Text = Scn_by_name(m_pFile, ".text")->PointerToRawData + (unsigned char*)m_pFile;

	// 把文件偏移保存一下压缩的时候要使用
	m_Text = Sec_Text;

	// 2.1 开始加密
	for(int i=0;i< m_StubInfo.g_Conf->encrypt_size;i++)
	{
		Sec_Text[i] ^= m_StubInfo.g_Conf->encrypt_key;
	}

	printf("加密完成!");

}

void MySell::Compress_Text()
{
	// 1.区段的大小
	int Length = m_StubInfo.g_Conf->encrypt_size;

	// 2.分配空间
	char* workmem = (char*)malloc(aP_workmem_size(Length));
	char* CompreData = (char*)malloc(aP_max_packed_size(Length));

	// 3.开始压缩
	size_t OutLength = aPsafe_pack(
		m_Text,      //要被压缩的数据
		CompreData,//接收被压缩的数据
		Length,    //被压缩数据的大小
		workmem,   //？？0
		NULL, NULL);

	// 判断是否压缩成功
	if (OutLength == APLIB_ERROR) {
		printf("压缩数据出错!!\n");
	}
	else {
		// 把压缩后的数据写到原位置覆盖掉
		memcpy(m_Text, CompreData, OutLength);

		printf("压缩前 %u bytes 压缩后 %u bytes\n", Length, OutLength);

		// 把压缩后的大小保存到dll
		m_StubInfo.g_Conf->compress_size = OutLength;

		// 开始释放资源
		free(workmem);
		free(CompreData);

		// 把区段往前移动

		// 1.计算压缩后文件对齐的大小
		DWORD Distance=Alignment(OutLength, m_pNT->OptionalHeader.FileAlignment);

		// 1.获取第1个区段首地址
		PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(m_pNT);

		// 2.获取区段个数
		int SecNuber=m_pNT->FileHeader.NumberOfSections;

		char* Source = m_pFile + pSection[0].PointerToRawData + Distance;
		char* Target = NULL;

		for(int i=1;i< SecNuber;i++)
		{
			// 1.先获取要移动到哪里 
			
			Target = m_pFile + pSection[i].PointerToRawData;

			// 2.计算要移动多大
			DWORD Target_Size = pSection[i].SizeOfRawData;

			// 4.申请一段堆空间保存要移动的数据
			char* Temp_Buff = (char*)malloc(sizeof(char) * Target_Size);

			// 5.把数据拷贝到目标地址 
			memcpy(Temp_Buff, Target, Target_Size);
			memcpy(Source, Temp_Buff, Target_Size);

			// 6.释放空间
			free(Temp_Buff);

			// 7.修改文件偏移
			pSection[i].PointerToRawData = Source-m_pFile;

			// 7.计算下一个要移动到哪里 
			Source = m_pFile+ pSection[i].PointerToRawData+ pSection[i].SizeOfRawData;

		}
		m_Size -= Length - OutLength;

	}


}

void MySell::SaveFile()
{
	// 1. 打开一个文件
	FILE* file = fopen("E:\\MySell\\Release\\test_pack.exe", "wb");
	fwrite(m_pFile, 1, m_Size, file);
	fclose(file);

	// 5. 释放内存
	free(m_pFile);
}
