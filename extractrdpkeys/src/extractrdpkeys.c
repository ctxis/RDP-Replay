/**
 * Copyright 2014 Context Information Security
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma comment(lib, "crypt32.lib")

#define _WIN32_WINNT 0x0400
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <tchar.h>
#include <stdbool.h>

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

/* 
Ensure that the Windows SDK (8.1) is installed: http://msdn.microsoft.com/en-us/windows/desktop/bg162891.aspx

The application can be compiled with mingw:

gcc extractrdpkeys.c -L"C:\Program Files (x86)\Windows Kits\8.1\Lib\winv6.3\um\x64" -lcrypt32 -m64 -o extractrdpkeys.x64.exe
gcc extractrdpkeys.c -L"C:\Program Files (x86)\Windows Kits\8.1\Lib\winv6.3\um\x86" -lcrypt32 -m32 -o extractrdpkeys.x86.exe
*/

int main()
{
	LONG lResult;
	HKEY hkReg = NULL;
	char *strSubKey = NULL;
	
	lResult = RegOpenKeyEx(
				HKEY_LOCAL_MACHINE,
				TEXT("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\RCM\\Secrets"),
				0,
				KEY_READ,
				&hkReg);
				
	if (lResult != ERROR_SUCCESS) {
		printf("Key not found.\n");
        return;
	}

	return QueryKey(hkReg);
}

int QueryKey(HKEY hKey) 
{ 
    TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
    DWORD    cbName;                   // size of name string 
    TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
    DWORD    cchClassName = MAX_PATH;  // size of class string 
    DWORD    cSubKeys=0;               // number of subkeys 
    DWORD    cbMaxSubKey;              // longest subkey size 
    DWORD    cchMaxClass;              // longest class string 
    DWORD    cValues;              // number of values for key 
    DWORD    cchMaxValue;          // longest value name 
    DWORD    cbMaxValueData;       // longest value data 
    DWORD    cbSecurityDescriptor; // size of security descriptor 
    FILETIME ftLastWriteTime;      // last write time 
 
    DWORD i, retCode; 
 
    TCHAR  achValue[MAX_VALUE_NAME]; 
    DWORD cchValue = MAX_VALUE_NAME; 
 
    // Get the class name and the value count. 
    retCode = RegQueryInfoKey(
        hKey,                    // key handle 
        achClass,                // buffer for class name 
        &cchClassName,           // size of class string 
        NULL,                    // reserved 
        &cSubKeys,               // number of subkeys 
        &cbMaxSubKey,            // longest subkey size 
        &cchMaxClass,            // longest class string 
        &cValues,                // number of values for this key 
        &cchMaxValue,            // longest value name 
        &cbMaxValueData,         // longest value data 
        &cbSecurityDescriptor,   // security descriptor 
        &ftLastWriteTime);       // last write time 

    if (cValues) 
    {
        for (i=0, retCode=ERROR_SUCCESS; i<cValues; i++) 
        { 
            cchValue = MAX_VALUE_NAME; 
            achValue[0] = '\0'; 
		
			DATA_BLOB pDataIn;
			DATA_BLOB pDataOut;
			
			void* pData = malloc(MAX_VALUE_NAME);
			if(NULL == pData)
			{
				_tprintf(_T("Malloc failed!\n"));
				return - 1;
			}
			
			DWORD valueSize = 0;
			
            retCode = RegEnumValue(hKey, i, 
                achValue, 
                &cchValue, 
                NULL, 
                NULL,
                pData,
                &valueSize);
 
			if (retCode != ERROR_SUCCESS && retCode != ERROR_MORE_DATA) 
            { 
				_tprintf("Failed to retrieve registry value: %d\n", retCode); 
				return -1;
            } 
			
			pData = malloc(valueSize);
			retCode = RegEnumValue(hKey, i, 
                achValue, 
                &cchValue, 
                NULL, 
                NULL,
                pData,
                &valueSize);
 
            if (retCode != ERROR_SUCCESS ) 
            { 
				_tprintf("Failed to retrieve registry value: %d\n", retCode); 
				return -1;
            } 
			
			_tprintf(_T("Value: %s\n"), achValue);
			
			DWORD cbDataInput = sizeof(pData);
			pDataIn.pbData = (LPBYTE)pData;    
			pDataIn.cbData = valueSize;
			
			if (CryptUnprotectData(
					&pDataIn,
					NULL,
					NULL,                 
					NULL,                 
					NULL,        
					1,
					&pDataOut)){
					
				char buff[256];
				printf("Decrypted Data: %s\n", pDataOut.pbData);
				sprintf(buff,".\\%s.bin", achValue);
				FILE* file = fopen(buff, "wb");
				fwrite( pDataOut.pbData, 1, pDataOut.cbData, file );
				fclose (file);
			}
			else {
				_tprintf(TEXT("Decryption failed\n")); 
			}
			
			free(pData);
			LocalFree(pDataOut.pbData);
        }
    }
	
	return 0;
}
