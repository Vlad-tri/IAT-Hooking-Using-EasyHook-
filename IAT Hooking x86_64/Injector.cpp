#include<tchar.h>
#include<stdio.h>
#include<Windows.h>
#include<easyhook.h>

int _tmain(int argc, _TCHAR* argv[]) {
	
	DWORD processId;
	wprintf(L"Enter the target process Id:\n");
	wscanf(L"%d", &processId);

	WCHAR* dllToInject = L"Hook.dll";
	wprintf(L"Attempting to inject %s\n\n", dllToInject);

	NTSTATUS nt = RhInjectLibrary(
		processId,
		0,
		EASYHOOK_INJECT_DEFAULT,
		NULL,
		dllToInject,
		NULL,
		0
		);

	if (nt != 0) {
		wprintf(L"RhInjectLibrary failed with error code = %d\n\n", nt);
		PWCHAR err = RtlGetLastErrorString();
		wprintf(err); wprintf(L"\n");
		return 1;
	}

	wprintf(L"Library Injected Successfully!!\n");
	wprintf(L"Press enter to exit\n\n");

	system("pause");

	return 0;
}