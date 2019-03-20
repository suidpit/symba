// simple_date_console.cpp: definisce il punto di ingresso dell'applicazione console.
//
#include "stdafx.h"

#include <windows.h>
#include <stdio.h>

int checktime(void);
void executePayload(void);

int main()
{
	if (checktime())
	{
		executePayload();
	}
}

void executePayload()
{
	printf("You got to the payload!\n");
}

int checktime()
{
	SYSTEMTIME x;
	GetSystemTime(&x);
	printf("Current day is %d", x.wDay);

	x.wDay += 4;
	x.wDay *= 3;

	if ((x.wDay == 21))
	{
		return 1;
	}
	return 0;
}
