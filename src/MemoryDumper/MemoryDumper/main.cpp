#include <windows.h>
#include <string>
#include <iostream>
#include <regex>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <fstream>
#include <mutex>
#pragma  comment(lib, "advapi32")

bool IsWoW64(DWORD pid) {
	bool success = false;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (hProcess != NULL) {
		USHORT status = 0;
		if (IsWow64Process2(hProcess, &status, NULL) != 0 && status != IMAGE_FILE_MACHINE_UNKNOWN) {
			success = true;
		}
		CloseHandle(hProcess);
	}
	return success;
}

std::string Trim(std::string str) {
	const char spacing[] = "\x20\x0A\x0D\x09\x10\x11\x12\x13";
	str.erase(0, str.find_first_not_of(spacing));
	str.erase(str.find_last_not_of(spacing) + 1);
	return str;
}

std::string Input(std::string msg) {
	printf(msg.append(": ").c_str());
	std::string var = "";
	getline(std::cin, var);
	return Trim(var);
}

bool IsPositiveNumber(std::string str) {
	const char numbers[] = "0123456789";
	return str.find_first_not_of(numbers) == std::string::npos;
}

bool StrToDWORD(std::string str, PDWORD out) {
	bool success = false;
	if (IsPositiveNumber(str)) {
		*out = std::strtoul(str.c_str(), NULL, 0);
		if (errno == ERANGE) {
			errno = 0;
		}
		else {
			success = true;
		}
	}
	return success;
}

std::vector<DWORD> GetProcessIDs() {
	std::vector<DWORD> pids;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("Cannot create the snapshot of current processes\n");
	}
	else {
		PROCESSENTRY32W entry = { };
		entry.dwSize = sizeof(entry);
		printf("################################# PROCESS LIST #################################\n");
		printf("#  %-6s  |  %-54.54s  |  %-4s  #\n", "PID", "NAME", "ARCH");
		printf("#----------------------------------------------------------------------------#\n");
		Process32FirstW(hSnapshot, &entry);
		do {
			printf("#  %-6lu  |  %-54.54ls  |   %-2s   #\n", entry.th32ProcessID, entry.szExeFile, IsWoW64(entry.th32ProcessID) ? "32" : "64");
		} while (Process32NextW(hSnapshot, &entry));
		printf("##################################### INFO #####################################\n");
		printf("# This PID : %-31lu Memory Dumper v1.1 by Ivan Sincek #\n", GetCurrentProcessId());
		printf("################################################################################\n");
		std::string input = Input("Enter proccess ID or name");
		if (input.length() < 1) {
			printf("\n");
			printf("Process ID or name is rquired\n");
		}
		else {
			DWORD pid = 0;
			bool numeric = StrToDWORD(input, &pid);
			std::wstring name = std::wstring(input.begin(), input.end());
			Process32FirstW(hSnapshot, &entry);
			do {
				if (numeric) {
					if (entry.th32ProcessID == pid) {
						pids.push_back(entry.th32ProcessID);
						break;
					}
				}
				else if (entry.szExeFile == name) {
					pids.push_back(entry.th32ProcessID);
				}
			} while (Process32NextW(hSnapshot, &entry));
			if (pids.size() < 1) {
				printf("\n");
				printf("Process does not exists\n");
			}
		}
		CloseHandle(hSnapshot);
	}
	return pids;
}

void EnableAccessTokenPrivs() {
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), (TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES), &hToken) == 0) {
		printf("Failed to enable access token privileges, cannot get the access token handle, moving on...\n");
		printf("\n");
	}
	else {
		struct priv {
			const char* name;
			bool set;
		};
		priv array[] = {
			{ "SeAssignPrimaryTokenPrivilege",             false },
			{ "SeAuditPrivilege",                          false },
			{ "SeBackupPrivilege",                         false },
			{ "SeChangeNotifyPrivilege",                   false },
			{ "SeCreateGlobalPrivilege",                   false },
			{ "SeCreatePagefilePrivilege",                 false },
			{ "SeCreatePermanentPrivilege",                false },
			{ "SeCreateSymbolicLinkPrivilege",             false },
			{ "SeCreateTokenPrivilege",                    false },
			{ "SeDebugPrivilege",                          false },
			{ "SeDelegateSessionUserImpersonatePrivilege", false },
			{ "SeEnableDelegationPrivilege",               false },
			{ "SeImpersonatePrivilege",                    false },
			{ "SeIncreaseBasePriorityPrivilege",           false },
			{ "SeIncreaseQuotaPrivilege",                  false },
			{ "SeIncreaseWorkingSetPrivilege",             false },
			{ "SeLoadDriverPrivilege",                     false },
			{ "SeLockMemoryPrivilege",                     false },
			{ "SeMachineAccountPrivilege",                 false },
			{ "SeManageVolumePrivilege",                   false },
			{ "SeProfileSingleProcessPrivilege",           false },
			{ "SeRelabelPrivilege",                        false },
			{ "SeRemoteShutdownPrivilege",                 false },
			{ "SeRestorePrivilege",                        false },
			{ "SeSecurityPrivilege",                       false },
			{ "SeShutdownPrivilege",                       false },
			{ "SeSyncAgentPrivilege",                      false },
			{ "SeSystemEnvironmentPrivilege",              false },
			{ "SeSystemProfilePrivilege",                  false },
			{ "SeSystemtimePrivilege",                     false },
			{ "SeTakeOwnershipPrivilege",                  false },
			{ "SeTcbPrivilege",                            false },
			{ "SeTimeZonePrivilege",                       false },
			{ "SeTrustedCredManAccessPrivilege",           false },
			{ "SeUndockPrivilege",                         false },
			{ "SeUnsolicitedInputPrivilege",               false }
		};
		int size = sizeof(array) / sizeof(array[0]);
		for (int i = 0; i < size; i++) {
			TOKEN_PRIVILEGES tp = { };
			if (LookupPrivilegeValueA(NULL, array[i].name, &tp.Privileges[0].Luid) != 0) {
				tp.PrivilegeCount = 1;
				tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
				if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL) != 0 && GetLastError() == ERROR_SUCCESS) {
					array[i].set = true;
				}
			}
		}
		CloseHandle(hToken);
	}
}

std::vector<std::string> DumpProcessMemory(std::vector<DWORD> pids) {
	std::vector<std::string> files;
	for (DWORD pid : pids) {
		HANDLE hProcess = OpenProcess((PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ), FALSE, pid);
		if (hProcess == NULL) {
			printf("PID [%-5ld]: Cannot get the process handle\n", pid);
		}
		else {
			std::string file = std::string("proc_mem_").append(std::to_string(pid)).append(".dmp");
			HANDLE hFile = CreateFileA(file.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile == INVALID_HANDLE_VALUE) {
				printf("PID [%-5ld]: Cannot create \"%s\"\n", pid, file.c_str());
			}
			else if (MiniDumpWriteDump(hProcess, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL) == 0) {
				CloseHandle(hFile);
				DeleteFileA(file.c_str());
				printf("PID [%-5ld]: Cannot dump the process memory\n", pid);
			}
			else {
				files.push_back(file);
				printf("PID [%-5ld]: Process memory has been successfully dumped to \"%s\"\n", pid, file.c_str());
				CloseHandle(hFile);
			}
			CloseHandle(hProcess);
		}
	}
	return files;
}

std::vector<std::string> ReadLines(std::string file) {
	std::vector<std::string> lines;
	std::ifstream stream(file.c_str());
	if (stream.fail()) {
		printf("Cannot open \"%s\"\n", file.c_str());
	}
	else {
		std::string line = "";
		while (getline(stream, line)) {
			lines.push_back(line);
		}
		if (lines.size() < 1) {
			printf("\"%s\" is empty\n", file.c_str());
		}
		stream.close();
	}
	return lines;
}

std::string GetFileContent(std::string file) {
	std::string data = "";
	HANDLE hFile = CreateFileA(file.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Cannot open \"%s\"\n", file.c_str());
	}
	else {
		DWORD size = GetFileSize(hFile, NULL);
		if (size == INVALID_FILE_SIZE) {
			printf("Cannot get the file size of \"%s\"\n", file.c_str());
		}
		else if (size < 1) {
			printf("\"%s\" is empty\n", file.c_str());
		}
		else {
			char* buffer = new char[4096];
			DWORD bytes = 0;
			while (size > 0) {
				if (ReadFile(hFile, buffer, 4096, &bytes, NULL) == FALSE) {
					data.clear();
					printf("Failed to read from \"%s\"\n", file.c_str());
					break;
				}
				data.append(buffer, bytes);
				size -= bytes;
			}
			delete[] buffer;
		}
		CloseHandle(hFile);
	}
	return data;
}

class LockedFile {
private:
	std::string file;
	std::mutex mutex;
public:
	LockedFile(std::string path) {
		file = path;
	}
	void Append(std::string data) {
		std::lock_guard<std::mutex> lock(mutex);
		std::ofstream stream(file.c_str(), std::ios::app);
		if (!stream.fail()) {
			stream.write(data.c_str(), data.length());
			stream.close();
		}
	}
};

void Grep(std::string content, std::string expression, std::shared_ptr<LockedFile> out) {
	std::regex regex = std::regex(expression);
	std::sregex_iterator begin = std::sregex_iterator(content.begin(), content.end(), regex);
	std::sregex_iterator end = std::sregex_iterator();
	for (std::sregex_iterator i = begin; i != end; ++i) {
		std::smatch match = *i;
		out->Append(match.str() + "\n");
	}
}

std::string Timestamp() {
	std::string formatted = "";
	time_t now = time(NULL);
	struct tm time = { };
	char buffer[16] = "";
	if (now != -1 && localtime_s(&time, &now) == 0 && strftime(buffer, sizeof(buffer), "%H:%M:%S", &time) != 0) {
		formatted = buffer;
	}
	return formatted;
}

void Pause() {
	printf("\n"); printf("Press any key to continue . . . "); (void)getchar(); printf("\n");
}

int main() {
	SetConsoleTitleA("Memory Dumper");
	std::vector<DWORD> pids = GetProcessIDs();
	if (pids.size() > 0) {
		printf("\n");
		std::string file = Input("Enter file with regular expressions");
		printf("\n");
		std::vector<std::string> expressions = ReadLines(file);
		if (expressions.size()) {
			EnableAccessTokenPrivs();
			std::vector<std::string> files = DumpProcessMemory(pids);
			if (files.size() > 0) {
				printf("\n");
				std::vector<std::thread> threads;
				for (std::string file : files) {
					std::string content = GetFileContent(file);
					if (content.length() > 0) {
						printf("[ %-8s ] Grepping \"%s\"\n", Timestamp().c_str(), file.c_str());
						std::shared_ptr<LockedFile> out = std::make_shared<LockedFile>(file + ".txt");
						for (std::string expression : expressions) {
							threads.push_back(std::thread(Grep, content, expression, out));
						}
					}
				}
				for (std::thread& thread : threads) {
					thread.join();
				}
				printf("\n");
				printf("[ %-8s ] Grepping is done\n", Timestamp().c_str());
			}
		}
	}
	Pause();
	return 0;
}