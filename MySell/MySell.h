#pragma once
#include<Windows.h>

class MySell{
public:
	MySell(const char* FilePath);
	~MySell();

	PIMAGE_DOS_HEADER pDos = nullptr;



};