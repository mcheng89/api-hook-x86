#include <string>
#include <windows.h>
#include "Tlhelp32.h"
#include <iostream>
#include <fstream>
  
#define MAXWAIT 10000
 
using namespace std;
  
DWORD GetProcessID( char* szName )
{
  PROCESSENTRY32   uProcess;        // Process Entry Struct
  HANDLE        hSnapShot   = 0;   // Snapshot Handle
  BOOL      pFound   = 0;   // Process Found Boolean

  // Setup Struct And Create Snapshot
  uProcess.dwSize = sizeof( uProcess );
  hSnapShot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
  pFound = Process32First( hSnapShot, &uProcess );

  // Loop Process List While A Process Is Found
  while( pFound )
  {
    // Compare Found Process Name To Given Process
    uProcess.dwSize = sizeof( uProcess );
    if( stricmp( uProcess.szExeFile, szName ) == 0 )
    {
      // Found Process Return ID
      return uProcess.th32ProcessID;
    }
    // Get Next Process
    pFound = Process32Next( hSnapShot, &uProcess );
  }
  // Close Snapshot Handle
  CloseHandle( hSnapShot );
  return 0; // Not Found
} 
  
bool insertDll(DWORD procID, std::string dll)
{
  //Find the address of the LoadLibrary api, luckily for us, it is loaded in the same address for every process
  HMODULE hLocKernel32 = GetModuleHandle("Kernel32");
  FARPROC hLocLoadLibrary = GetProcAddress(hLocKernel32, "LoadLibraryA");
    
  //Adjust token privileges to open system processes
  HANDLE hToken;
  TOKEN_PRIVILEGES tkp;
  if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
  {
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL);
  }

  //Open the process with all access
  HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    
  //cout << hProc << endl;

  //Allocate memory to hold the path to the Dll File in the process's memory
  dll += '';
  LPVOID hRemoteMem = VirtualAllocEx(hProc, NULL, dll.size(), MEM_COMMIT, PAGE_READWRITE);
    
  //cout << hRemoteMem << endl;

  //Write the path to the Dll File in the location just created
  DWORD numBytesWritten;
  WriteProcessMemory(hProc, hRemoteMem, dll.c_str(), dll.size(), &numBytesWritten);

  //Create a remote thread that starts begins at the LoadLibrary function and is passed are memory pointer
  HANDLE hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)hLocLoadLibrary, hRemoteMem, 0, NULL);

  //cout << hRemoteThread << endl;

  //Wait for the thread to finish
  bool res = false;
  if (hRemoteThread)
    res = (bool)WaitForSingleObject(hRemoteThread, MAXWAIT) != WAIT_TIMEOUT;

  //Free the memory created on the other process
  //#define MEM_RELEASE 42
  VirtualFreeEx(hProc, hRemoteMem, 0, MEM_RELEASE);

  //Release the handle to the other process
  CloseHandle(hProc);

  return res;
}
 
char* ExtractBinResource(std::string strCustomResName, LPSTR nResourceId)
                //int nResourceId
                //std::string strOutputName)
{
  HGLOBAL hResourceLoaded;  // handle to loaded resource
  HRSRC   hRes;             // handle/ptr to res. info.
  char    *lpResLock;     // pointer to resource data
  DWORD   dwSizeRes;
    
  char *strOutputLocation = new char[MAX_PATH];
  /*GetCurrentDirectory(MAX_PATH,strOutputLocation);
  strOutputLocation = strcat(strOutputLocation, "\\DLLHook.dll");*/
  GetTempPath(MAX_PATH,strOutputLocation);
  GetTempFileName(strOutputLocation, // directory for tmp files
                            "NEW",        // temp file name prefix
                            0,            // create unique name
                            strOutputLocation);  // buffer for name 

  // lets get the app location
  /*strAppLocation = getAppLocation();
  strOutputLocation = strAppLocation += "\\";
  strOutputLocation += strOutputName;*/

  hRes = FindResource(NULL, 
                      nResourceId, //MAKEINTRESOURCE(nResourceId), 
                      strCustomResName.c_str()
                  );

  hResourceLoaded = LoadResource(NULL, hRes);
  lpResLock = (char *) LockResource(hResourceLoaded);
  dwSizeRes = SizeofResource(NULL, hRes);

  std::ofstream outputFile(strOutputLocation, std::ios::binary);
  outputFile.write((const char *) lpResLock, dwSizeRes);
  outputFile.close();
    
  return strOutputLocation;
}
 
int main()
{
  //ExtractBinResource("DLL", , "DLLHook.dll");
  //cout << "Waiting for you to open up Internet Explorer" << endl;
  char* szName = "IEXPLORE.EXE";
  /*int hProcess;
  do{
    hProcess = GetProcessID(szName);
    Sleep(1);
  }while(hProcess == 0);*/
    
  //if (GetProcessID(szName) != 0)
  //*******************************************************************************
  PROCESS_INFORMATION ProcessInfo; //This is what we get as an [out] parameter
  STARTUPINFO StartupInfo; //This is an [in] parameter
  ZeroMemory(&StartupInfo, sizeof(StartupInfo));
  StartupInfo.cb = sizeof StartupInfo; //Only compulsory field
  if(CreateProcess("C:/Program Files/Internet Explorer/IEXPLORE.EXE", NULL, NULL,NULL,FALSE,0,NULL, NULL,&StartupInfo,&ProcessInfo))
  //*******************************************************************************
  {
    char *acDir = ExtractBinResource("DLL", "DLLHOOK");/*new char[MAX_PATH];
    GetCurrentDirectory(MAX_PATH,acDir);
    acDir = strcat(acDir, "\\DLLHook.dll");*/
    cout << acDir << endl;
    //strcpy(acDir, "DLLHook.dll");

    cout << GetProcessID(szName) << endl;
    cout << insertDll(GetProcessID(szName), acDir) << endl;
    LPVOID lpMessageBuffer;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), LANG_USER_DEFAULT, (LPSTR)&lpMessageBuffer, 0, NULL);
    cout << "Error Code " << GetLastError() << ": " << (LPCTSTR)lpMessageBuffer;
    LocalFree( lpMessageBuffer );
    //MessageBox(NULL,"Proxy loaded.","IEProxy v4.0.2",NULL);
  }
  return 0;
}