#include"MySell.h"

int main()
{
	// 创建加壳对象 
	MySell Myself("E:\\MySell\\Release\\test.exe");

	// 修改区段信息
	Myself.Add_Section();

	// 加密代码段
	Myself.Encryption_Text();

	// 压缩代码段
	Myself.Compress_Text();

	// 修改其它信息
	Myself.Alter_Other();

	//把加壳后的程序保存到文件
	Myself.SaveFile();

	system("pause");
	return 0;
}