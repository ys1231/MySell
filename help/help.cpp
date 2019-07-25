
void main()
{
	_asm
	{
		jmp l2
		_EMIT 0x1//这里就是花指令
		_EMIT 0x2//这里就是花指令
		_EMIT 0x3//这里就是花指令
		_EMIT 0x4//这里就是花指令
		l2:
		mov eax, 0x11111111
	}
}