/**
 * Il secondo POC introduce una problematica un po' più ostica da trattare.
 * Cosa succede se inseriamo una dipendenza globale ad un valore che viene concretizzato
 * PRIMA del blocco che contiene la chiamata ad una Trigger source?
 *
 * In realtà, angr concretizza già i valori globali nei segmenti di data quando
 * il progetto viene creato, quindi si riesce a gestire questa situazione.
 */

#include "stdafx.h"

#include <windows.h>
#include <stdio.h>

int checktime(void);
void executePayload(void);

int dayOfTheEnd = 21;

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

	printf("Current day is %d\n", x.wDay);

	x.wDay += 4;
	x.wDay *= 3;


	if ((x.wDay == dayOfTheEnd))
	{
		return 1;
	}
	return 0;
}
