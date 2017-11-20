#include<tchar.h>
#include<stdio.h>
#include<Windows.h>
#include<easyhook.h>
#include<winNT.h>

#pragma comment(lib,"NtDll.lib")

NTSTATUS NtCreateFileHook(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
	) {
	MessageBox(GetActiveWindow(), (LPCSTR)ObjectAttributes->ObjectName->Buffer, (LPCSTR)L"Object Name", MB_OK);
	return NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
		CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo) {

	HOOK_TRACE_INFO hHook = { NULL };

	NTSTATUS res = LhInstallHook(
		GetProcAddress(GetModuleHandle("ntdll"), "NtCreateFile"),
		NtCreateFileHook,
		NULL,
		&hHook);

	if (FAILED(res)) {
		MessageBox(GetActiveWindow(), (LPCSTR)RtlGetLastErrorString(), (LPCSTR)L"Failed to install hook", MB_OK);
	}

	ULONG ACLEntries[1] = { 0 };

	LhSetExclusiveACL(ACLEntries, 1, &hHook);

	return;
}