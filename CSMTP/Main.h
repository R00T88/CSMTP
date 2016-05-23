#pragma once

//=======================================================================
// Include
//=======================================================================
#include <atlbase.h>
#include <atlconv.h>

#include <iostream>
#include <sstream>
#include <strsafe.h>

#include <vector>
#include <string.h>
#include <assert.h>

#include <winsock2.h>
#include <time.h>
#pragma comment(lib, "ws2_32.lib")

#include "Security\base64.h"

/* Fix OpenSSL VS2015 */
#define _WINSOCK_DEPRECATED_NO_WARNINGS

/* Fix OpenSSL VS2015 */
FILE _iob[] = { *stdin, *stdout, *stderr };
extern "C" FILE * __cdecl __iob_func(void) { return _iob; }

#include "SMTP\CSmtp.h"

#include "Util\Util.h"
#include "Console\Console.h"

//=======================================================================
// Global
//=======================================================================
int iResult;