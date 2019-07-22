#include"MySell.h"
#include <cstdio>
#include <cstdlib>

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
	int File_Size = 0;
	fseek(file, 0, SEEK_END);

	File_Size = ftell(file);
	// 重新定位指向文件开头的文件指针
	rewind(file);

	char* File_buff = (char*)malloc(File_Size);
	fread(File_buff, 1, File_Size, file);
	fclose(file);


}
