#include"MySell.h"

int main()
{
	// 创建加壳对象 
	MySell Myself("E:\\MySell\\Release\\test.exe");

	Myself.Add_Section();

	Myself.Alter_Other();

	Myself.SaveFile();

	return 0;
}