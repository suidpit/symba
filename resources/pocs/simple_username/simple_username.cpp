#include "stdafx.h"

#include <string.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    char username[32];
    size_t i;
    DWORD usersize = sizeof(username);

    printf("Getting username...\n");

    GetUserName(username, &usersize);

    printf("You are %s, aren't you?\n", username);

    if (strncmp(username, "PIETRO", 6) != 0) {
        exit(-1);
    }

    printf("Ok, %s, you can pass.\n", username);
    exit(1);
}