/**
 * Il problema iniettato in questo POC tocca in pieno le difficoltà della symbolic execution.
 * Come gestire casi in cui il valore sia stato iniettato e concretizzato PRIMA dello starting point
 * dell'esecuzione simbolica?
 */

#include "stdafx.h"

#include <windows.h>
#include <stdio.h>

int checktime(int *ptr, int size);
void executePayload(void);

int main()
{
	int interesting_days[] = {11, 26, 31};

	if (checktime(interesting_days, 3))
	{
		executePayload();
	}
}

void executePayload()
{
	printf("You got to the payload!\n");
}

int checktime(int *ptr, int size)
{
	char FOUND = false;

	SYSTEMTIME x;
	GetSystemTime(&x);
	printf("Current day is %d\n", x.wDay);

	for (int i = 0; i < 3; i++)
	{
		if (ptr[i] == x.wDay)
		{
			FOUND = true;
		}
	}

	if (FOUND)
	{
		return 1;
	}
	return 0;
}
