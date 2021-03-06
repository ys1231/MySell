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
		size_t Orig_Size = aPsafe_get_orig_size(Text);

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

	// 弹密码框

	//窗口回调函数
	LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		DEFAPI("Kernel32.dll", GetModuleHandleW);
		DEFAPI("user32.dll", CreateWindowExW);
		DEFAPI("user32.dll", PostQuitMessage);
		DEFAPI("user32.dll", DefWindowProcW);
		DEFAPI("user32.dll", GetWindowTextA);
		DEFAPI("user32.dll", MessageBoxA);
		DEFAPI("user32.dll", GetDlgItem);
		DEFAPI("user32.dll", ShowWindow);
		
		//消息处理
		switch (msg)
		{
			//窗口被创建
		case WM_CREATE:
		{   
			// 创建接收密码框
			My_CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT", NULL,
				WS_CHILD | WS_VISIBLE | WS_BORDER,50, 20,120, 30,
				hwnd,(HMENU)0x1001,NULL,NULL);

			// 创建按钮
			My_CreateWindowExW(0,L"button", L"确定", WS_CHILD | WS_VISIBLE,
				70, 60,60, 20,hwnd,(HMENU)0x1002,NULL,NULL);

			return 0;
		}
			// 响应标准控件消息
		case WM_COMMAND:
		{
			// 控件ID
			DWORD ID = LOWORD(wParam);

			// 消息通知码
			DWORD code = HIWORD(wParam);
			
			if (ID == 0x1002 && code == BN_CLICKED)
			{
				// 获取密码框句柄
				HWND hEdit = My_GetDlgItem(hwnd, 0x1001);
				
				// 保存密码的
				char buff[5]={};
				//char str[5] = { '1','5','p','b','\0' };
				//char str[5] = "15pb";

				DWORD flag = 0;

				// 从空间获取密码
				My_GetWindowTextA(hEdit, buff, 5);

				// 进行密码验证
				__asm
				{
					pushad
					mov ecx, 0x4
					lea edi, g_conf.str_key
					lea esi, buff
					cld
					repe cmpsb
					jnz No
					mov flag, 1
					jmp End
				No :
					mov flag, 0
				End :
					popad
				}

				if (flag)
				{
					// 密码正确关闭弹框
					My_ShowWindow(hwnd, SW_HIDE);
					My_PostQuitMessage(0);
					return 0;
				}
				else
				{
					My_MessageBoxA(0, "密码错误!", 0, MB_OK);
				}
			}
			break;
		}
		//窗口销毁
		case WM_DESTROY:
		{
			// 直接结束进程
			DEFAPI("kernel32.dll", ExitProcess);
			My_ExitProcess(0);
		}
		}
		//让Windows以默认的方式来处理没有处理的消息。	
		return My_DefWindowProcW(hwnd, msg, wParam, lParam);
	}

	//弹出密码验证框
	void UserCheck()
	{
		DEFAPI("Kernel32.dll", GetModuleHandleW);
		DEFAPI("user32.dll", RegisterClassW);
		DEFAPI("gdi32.dll", GetStockObject);
		DEFAPI("user32.dll", CreateWindowExW);
		DEFAPI("user32.dll", ShowWindow);
		DEFAPI("user32.dll", UpdateWindow);
		DEFAPI("user32.dll", GetMessageW);
		DEFAPI("user32.dll", TranslateMessage);
		DEFAPI("user32.dll", DispatchMessageW);


		// 1.设计一个窗口类（为窗口类的各个字段赋值）
		WNDCLASS wc;//定义一个窗口类
		static TCHAR szClassName[] = TEXT("我是一个壳");//窗口类名

		wc.style = CS_HREDRAW | CS_VREDRAW;//窗口类的风格（一般为这两个风格，表示窗口拉伸时重绘窗口）
		wc.cbClsExtra = 0;//分派给窗口类的扩展的字节数（额外内存）
		wc.cbWndExtra = 0;//分派给窗口实例的扩展的字节数（额外内存）
		wc.hIcon = 0;//窗口图标
		wc.hCursor = 0;//鼠标样式
		wc.hbrBackground = (HBRUSH)My_GetStockObject(WHITE_BRUSH);//窗口背景画刷
		wc.lpszMenuName = NULL;//窗口菜单
		wc.hInstance = My_GetModuleHandleW(NULL);//当前窗口句柄
		wc.lpfnWndProc = WndProc;//指向窗口过程的指针(重要!!必填)	
		wc.lpszClassName = szClassName;//窗口类名（重要!!必填）

		// 2.注册窗口
		My_RegisterClassW(&wc);

		// 3.创建窗口
		HWND hwnd;//定义一个窗口句柄
		hwnd = My_CreateWindowExW(
			0,//窗口扩展风格
			szClassName,//窗口类的名字
			TEXT("密码"),//窗口标题
			WS_OVERLAPPEDWINDOW,//窗口风格
			400,//初始化时x轴的位置
			400,//初始化时y轴的位置
			240,//窗口宽度
			150,//窗口高度
			NULL,//父窗口句柄
			NULL,//窗口菜单句柄
			My_GetModuleHandleW(NULL),//当前窗口的句柄
			NULL//为窗口附加补充信息
		);

		// 4.显示窗口、更新绘制窗口	
		My_ShowWindow(hwnd, SW_SHOW);
		My_UpdateWindow(hwnd);

		// 5.消息循环
		MSG msg;//定义一个消息
		//GetMessage这个函数获取到WM_QUIT消息的时候，会返回false
		while (My_GetMessageW(&msg, NULL, 0, 0))//NULL表示捕获所有窗口的消息，后面两个0表示捕获所有的消息
		{
			My_TranslateMessage(&msg);
			My_DispatchMessageW(&msg);//分派消息到窗口过程
		}
	}

	// 修复重定位函数
	void Alter_Reloc() {

		DEFAPI("kernel32.dll", VirtualProtect);

		PIMAGE_BASE_RELOCATION pRel = (PIMAGE_BASE_RELOCATION)(g_conf.OldRelocAddress+ GetBaseAddress());
		_asm {
			pushad
			mov eax,g_conf.OldRelocAddress
			popad
		}
		typedef struct _Offset {
			WORD offset : 12; //重定位项的RVA+内存页起始就是 文件中的需要修正的偏移
			WORD type : 4; 	//0 占位符  不做修正  如果是32位 就是3 修正4个字节  64位 10 修正8
		}Offset, * PTypeOffset;

			// 遍历出所有的重定位项
		while (pRel->SizeOfBlock)
		{

			PTypeOffset type_offset = (PTypeOffset)(pRel + 1);
			DWORD count = (pRel->SizeOfBlock - 8) / 2;
			for (DWORD i = 0; i < count; ++i) {
				if (type_offset[i].type == 3) {
					DWORD rel_item_rva = type_offset[i].offset + pRel->VirtualAddress;
					DWORD* rel_addr = (DWORD*)(rel_item_rva + GetBaseAddress());
					
					DWORD old;
					My_VirtualProtect(rel_addr, 4, PAGE_READWRITE, &old);
					*rel_addr = (ULONG_PTR)* rel_addr - 0x400000 + GetBaseAddress();
					My_VirtualProtect(rel_addr, 4, old, &old);
				}
			}
			pRel = (IMAGE_BASE_RELOCATION*)
				((char*)pRel + pRel->SizeOfBlock);
		}
	}

	
	// IAT加密
	void Alter_IAT() {
		_asm
		{
			jmp l2
			_EMIT 0x1
			_EMIT 0x2
			_EMIT 0x3
			_EMIT 0x4
			l2:
			mov eax, 0x22222222
		}
		DEFAPI("kernel32.dll", VirtualAlloc);
		DEFAPI("kernel32.dll", LoadLibraryA);
		DEFAPI("kernel32.dll", GetProcAddress);
		DEFAPI("kernel32.dll", VirtualProtect);
		DEFAPI("user32.dll", MessageBoxA);
		

		// 获取模块基址 
		DWORD pBuff = GetBaseAddress();

		// 获取导入表的位置
		PIMAGE_IMPORT_DESCRIPTOR l_pImport = (PIMAGE_IMPORT_DESCRIPTOR)(g_conf.Import_Rva + pBuff);

		// 获取到的函数地址
		DWORD Function_Address = 0 ;

		// 存放ShellCode 
		const DWORD Size = 17;		
		char Shellcode[Size] ="\x53\x5B\x40\x83\xE9\x34\x83\xE8\x01\x68\x00\x00\x00\x00\xC3" ;
		// 申请的对空间首地址
		char* Heap_Space = NULL;
		
		//遍历导入表和 里面的函数
		while (l_pImport->Name)
		{
			//打印模块名
			char* ModuleName= (char*)(l_pImport->Name+ pBuff);

			// 获取INT表
			PIMAGE_THUNK_DATA l_pThunk = (PIMAGE_THUNK_DATA)(l_pImport->OriginalFirstThunk+ pBuff);  // NOLINT

			// 获取 NAT表首地址
			PIMAGE_THUNK_DATA l_pIAThunk= (PIMAGE_THUNK_DATA)(l_pImport->FirstThunk + pBuff);

			// 获取哦当前模块的基址
			HMODULE BaseAddress=My_LoadLibraryA(ModuleName);

			while (l_pThunk->u1.AddressOfData)
			{
				//判断导入方式   (最高位是否为1 )1 是序号导入 0是函数名导入
				if (IMAGE_SNAP_BY_ORDINAL(l_pThunk->u1.AddressOfData))
				{	
					Function_Address=(DWORD)My_GetProcAddress(BaseAddress,(char*)(l_pThunk->u1.Ordinal && 0xFFFF));
					//My_MessageBoxA(0, Function_Address, "ds", 0);
				}
				else
				{                                                                 
					//名称导入 
					PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(l_pThunk->u1.AddressOfData+ pBuff);
					Function_Address=(DWORD)My_GetProcAddress(BaseAddress, pName->Name);
					
					//My_MessageBoxA(0, pName->Name, "ds", 0);
				}
				//My_MessageBoxA(0, Function_Address, "ds", 0);
				// 把获取到的函数地址放到Shellcode里面

				*(DWORD*)&Shellcode[10] =Function_Address;


				//*(BYTE*)& Shellcode[10]= Function_Address& 0xFF000000;
				//*(BYTE*)& Shellcode[11]= Function_Address& 0xFF0000;
				//*(BYTE*)& Shellcode[12]= Function_Address& 0xFF00;
				//*(BYTE*)& Shellcode[13]= Function_Address& 0xFF;
				// 
				// 74183930
				/*FF00 0000
				 *00FF 0000
				 *0000 FF00
				 *0000 00FF
				 */
				
				
				
				
				// 申请对应的堆空间
				Heap_Space=(char*)My_VirtualAlloc(0, Size, MEM_COMMIT|0x2000, PAGE_EXECUTE_READWRITE);
				
				// 把shellcode放入对空间
				for (int i=0;i<=Size;i++)
				{
					Heap_Space[i] = Shellcode[i];
				}
				
				// 修改属性
				DWORD oldd = 0;
				My_VirtualProtect(l_pIAThunk, 4, PAGE_EXECUTE_READWRITE, &oldd);

				// 填充IAT
				l_pIAThunk->u1.Function = (DWORD)Heap_Space;
				//l_pIAThunk->u1.Function = Function_Address;

				//下一个函数
				l_pThunk++;

				// 下一个IAT
				l_pIAThunk++;
			}
			//下一个导入结构
			l_pImport++;
		}

	}
	


	_declspec(dllexport)
		void _declspec(naked) start() {

		// 花指令
		_asm
		{
			jmp l2
			_EMIT 0x1
			_EMIT 0x2
			_EMIT 0x3
			_EMIT 0x4
			l2:
			mov eax, 0x11111111
		}

		// 初始化两个重要函数的地址
		getApis();
		
		// 密码验证
		//UserCheck();

		// 解压缩
		DeCompress();

		// 解密
		Decode();

		// 修复重定位
		Alter_Reloc();

		Alter_IAT();
		//void encryptIAT();

		
		g_conf.oep+= GetBaseAddress();
		_asm jmp g_conf.oep;
	}


}
