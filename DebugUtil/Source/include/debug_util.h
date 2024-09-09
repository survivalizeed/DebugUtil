#pragma once

#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <map>
#include <optional>

namespace DEBUG_UTIL {
	struct Module {
		uintptr_t base, size;
	};

	struct Process {
		std::string name;
		HANDLE handle;
		DWORD id;
		Module _module;  // So we don't conflict with c++20+
	};

	enum class HWBP {
		HARDWARE_BREAKPOINT_1,
		HARDWARE_BREAKPOINT_2,
		HARDWARE_BREAKPOINT_3,
		HARDWARE_BREAKPOINT_4
	};


	class DBG {
		Process process;
		std::map<std::string, Module> modules;
		DEBUG_EVENT debug_event;
		DWORD continue_status;

		uintptr_t hardware_bp1, hardware_bp2, hardware_bp3, hardware_bp4;
		std::map<uintptr_t, BYTE> software_breakpoints;
		uintptr_t current_software_breakpoint_hit = 0;

		std::string wchar_to_string(const wchar_t* text) {
			int bufferSize = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
			std::string narrowStr(bufferSize, 0);
			WideCharToMultiByte(CP_UTF8, 0, text, -1, &narrowStr[0], bufferSize, nullptr, nullptr);
			return narrowStr;
		}

		std::string to_lower(const std::string& str) {
			std::string result = str;
			for (char& c : result) {
				c = std::tolower((unsigned char)c);
			}
			return result;
		}

		bool __get_process() {	
			HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
			PROCESSENTRY32 entry;
			entry.dwSize = sizeof(entry);
			do {
				auto exeFile = wchar_to_string(entry.szExeFile);
				exeFile = to_lower(exeFile);
				if (!strcmp(exeFile.c_str(), process.name.c_str())) {
					process.id = entry.th32ProcessID;
					CloseHandle(handle);
					process.handle = OpenProcess(PROCESS_ALL_ACCESS, false, process.id);
					return true;
				}
			} while (Process32Next(handle, &entry));
			return false;
		}

		std::optional<Module> __get_module(const std::string& name) {
			std::optional<Module> _module;
			HANDLE hmodule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process.id);
			MODULEENTRY32 mEntry;
			mEntry.dwSize = sizeof(mEntry);
			do {
				auto modName = wchar_to_string(mEntry.szModule);
				modName = to_lower(modName);
				if (!strcmp(modName.c_str(), (LPSTR)name.c_str())) {
					CloseHandle(hmodule);
					
					_module = { (uintptr_t)mEntry.hModule, (uintptr_t)mEntry.modBaseSize };
					return _module;
				}
			} while (Module32Next(hmodule, &mEntry));
			return std::nullopt;
		}

	public:

		DBG(const std::string& name) {
			process.name = name;
			__get_process();
			__get_module(process.name);
		}

		bool get_process() {
			if (__get_process())
				return true;
			return false;
		}

		void wait_for_process(void(*display_callback)(void), DWORD intervall) {
			for (;;) {
				display_callback();
				__get_process();
				Sleep(intervall);
			}
		}

		bool add_module(const std::string& name) {
			auto _module = __get_module(name);
			if (_module.has_value()) {
				modules[name] = _module.value();
				return true;
			}
			return false;
		}

		std::optional<Module> get_module(const std::string& name) {
			if (modules.find(name) != modules.end())
				return modules[name];
			return std::nullopt;
		}

		DWORD get_main_thread_id() {
			HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			THREADENTRY32 te32;
			te32.dwSize = sizeof(THREADENTRY32);
			DWORD dwMainThreadId = 0;
			if (Thread32First(hSnapshot, &te32))
			{
				do
				{
					if (te32.th32OwnerProcessID == process.id)
					{
						dwMainThreadId = te32.th32ThreadID;
						break;
					}
				} while (Thread32Next(hSnapshot, &te32));
			}
			CloseHandle(hSnapshot);
			return dwMainThreadId;
		}

		uintptr_t find_signature(const std::string& module_name, const std::string& signature, const std::string& mask) {
			auto memory_compare = [](const BYTE* data, const BYTE* mask, const char* szMask)
			{
					for (; *szMask; ++szMask, ++data, ++mask) {
						if (*szMask == 'x' && *data != *mask) {
							return false;
						}
					}
					return (*szMask == NULL);
			};		
			auto _module_op = get_module(module_name);
			if (!_module_op.has_value())
				return 0;
			auto _module = _module_op.value();
			BYTE* data = new BYTE[_module.size];
			SIZE_T bytesRead;
			ReadProcessMemory(process.handle, (LPVOID)_module.base, data, _module.size, &bytesRead);
			for (uintptr_t i = 0; i < _module.size; i++)
			{
				if (memory_compare((const BYTE*)(data + i), (const BYTE*)signature.c_str(), mask.c_str())) {
					return _module.base + i;
				}
			}
			delete[] data;
			return 0;
		}

		template <typename type>
			requires std::is_integral_v<type> || std::is_floating_point_v<type>
		bool write_memory(uintptr_t address, type Value) {
			return WriteProcessMemory(TargetProcess, (LPVOID)Address, &Value, sizeof(var), 0);
		}
	
		template <typename type>
			requires std::is_integral_v<type> || std::is_floating_point_v<type>
		type read_memory(uintptr_t Address) {
			type value;
			ReadProcessMemory(TargetProcess, (LPCVOID)Address, &value, sizeof(var), NULL);
			return value;
		}

		// Debugger section

		bool attach() const {
			if (DebugActiveProcess(process.id))
				return true;
			return false;
		}

		bool detach() const {
			if (DebugActiveProcessStop(process.id))
				return true;
			return false;
		}

		bool set_hardware_breakpoint(uintptr_t address, HWBP hwbp) {
			HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			THREADENTRY32 te;
			te.dwSize = sizeof(THREADENTRY32);

			if (Thread32First(hSnapshot, &te)) {
				do {
					if (te.th32OwnerProcessID == process.id) {
						HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
						if (hThread) {
							SuspendThread(hThread);

							CONTEXT ctx = { 0 };
							ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
							GetThreadContext(hThread, &ctx);

							switch (hwbp) {
							case HWBP::HARDWARE_BREAKPOINT_1:
								hardware_bp1 = address;
								ctx.Dr0 = address;				
								ctx.Dr7 |= 1;
								break;
							case HWBP::HARDWARE_BREAKPOINT_2:
								hardware_bp2 = address;
								ctx.Dr1 = address;
								ctx.Dr7 |= (1 << 2);
								break;
							case HWBP::HARDWARE_BREAKPOINT_3:
								hardware_bp3 = address;
								ctx.Dr2 = address;
								ctx.Dr7 |= (1 << 4);
								break;
							case HWBP::HARDWARE_BREAKPOINT_4:
								hardware_bp4 = address;
								ctx.Dr3 = address;
								ctx.Dr7 |= (1 << 6);
								break;
							default:
								break;
							}
							SetThreadContext(hThread, &ctx);
							ResumeThread(hThread);
							CloseHandle(hThread);
						}
					}
				} while (Thread32Next(hSnapshot, &te));
			}

			CloseHandle(hSnapshot);
		}

		bool remove_hardware_breakpoint(HWBP hwbp) {
			HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			THREADENTRY32 te;
			te.dwSize = sizeof(THREADENTRY32);
			if (Thread32First(hSnapshot, &te)) {
				do {
					if (te.th32OwnerProcessID == process.id) {
						HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
						if (hThread) {
							SuspendThread(hThread);
							CONTEXT ctx = { 0 };
							ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
							GetThreadContext(hThread, &ctx);
							switch (hwbp) {
							case HWBP::HARDWARE_BREAKPOINT_1:
								hardware_bp1 = 0;
								ctx.Dr0 = 0;
								ctx.Dr7 &= ~(1);
								break;
							case HWBP::HARDWARE_BREAKPOINT_2:
								hardware_bp2 = 0;
								ctx.Dr1 = 0;
								ctx.Dr7 &= ~(1 << 2);
								break;
							case HWBP::HARDWARE_BREAKPOINT_3:
								hardware_bp3 = 0;
								ctx.Dr2 = 0;
								ctx.Dr7 &= ~(1 << 4);
								break;
							case HWBP::HARDWARE_BREAKPOINT_4:
								hardware_bp4 = 0;
								ctx.Dr3 = 0;
								ctx.Dr7 &= ~(1 << 6);
								break;
							default:
								break;
							}
							SetThreadContext(hThread, &ctx);
							ResumeThread(hThread);
							CloseHandle(hThread);
						}
					}
				} while (Thread32Next(hSnapshot, &te));
			}

			CloseHandle(hSnapshot);
		}

		bool has_hardware_breakpoint_hit(HWBP hwbp) const {
			uintptr_t address = 0;
			switch (hwbp)
			{
			case DEBUG_UTIL::HWBP::HARDWARE_BREAKPOINT_1:
				address = hardware_bp1;
				break;
			case DEBUG_UTIL::HWBP::HARDWARE_BREAKPOINT_2:
				address = hardware_bp2;
				break;
			case DEBUG_UTIL::HWBP::HARDWARE_BREAKPOINT_3:
				address = hardware_bp3;
				break;
			case DEBUG_UTIL::HWBP::HARDWARE_BREAKPOINT_4:
				address = hardware_bp4;
				break;
			default:
				break;
			}
			if (debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
				auto exceptionCode = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
				if ((exceptionCode == EXCEPTION_SINGLE_STEP || exceptionCode == EXCEPTION_BREAKPOINT) &&
					debug_event.u.Exception.ExceptionRecord.ExceptionAddress == (void*)address) {
					return true;
				}
			}
			return false;
		}

		void hardware_breakpoint_handled() {
			continue_status = DBG_CONTINUE;
		}

		static void continue_after_hardware_breakpoint_hit(CONTEXT& context) {
			context.EFlags |= (1 << 16);
		}

		bool set_software_breakpoint(uintptr_t address) {
			BYTE original_byte;
			SIZE_T bytesRead;
			if (ReadProcessMemory(process.handle, (LPCVOID)address, &original_byte, sizeof(BYTE), &bytesRead) && bytesRead == sizeof(BYTE)) {
				software_breakpoints[address] = original_byte;
				BYTE int3 = 0xCC;
				SIZE_T bytesWritten;
				if (WriteProcessMemory(process.handle, (LPVOID)address, &int3, sizeof(BYTE), &bytesWritten) && bytesWritten == sizeof(BYTE)) {
					FlushInstructionCache(process.handle, (LPCVOID)address, sizeof(BYTE));
					return true;
				}
			}
			return false;
		}

		bool remove_software_breakpoint(uintptr_t address) {
			if (software_breakpoints.find(address) != software_breakpoints.end()) {
				BYTE original_byte = software_breakpoints[address];
				SIZE_T bytesWritten;
				if (WriteProcessMemory(process.handle, (LPVOID)address, &original_byte, sizeof(BYTE), &bytesWritten) && bytesWritten == sizeof(BYTE)) {
					FlushInstructionCache(process.handle, (LPCVOID)address, sizeof(BYTE));
					software_breakpoints.erase(address);
					return true;
				}
			}
			return false;
		}

		bool has_software_breakpoint_hit() {
			if (debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
				auto exceptionCode = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
				if (exceptionCode == EXCEPTION_BREAKPOINT) {
					uintptr_t hit_address = (uintptr_t)debug_event.u.Exception.ExceptionRecord.ExceptionAddress;
					if (software_breakpoints.find(hit_address) != software_breakpoints.end()) {
						return true;
					}
				}
			}
			return false;
		}

		bool software_breakpoint_handled() {
			BYTE original_byte = software_breakpoints[current_software_breakpoint_hit];
			WriteProcessMemory(process.handle, (LPVOID)current_software_breakpoint_hit, &original_byte, sizeof(BYTE), NULL);
			FlushInstructionCache(process.handle, (LPCVOID)current_software_breakpoint_hit, sizeof(BYTE));
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debug_event.dwThreadId);
			if (hThread) {
				CONTEXT ctx = { 0 };
				ctx.ContextFlags = CONTEXT_CONTROL; 
				GetThreadContext(hThread, &ctx);
				ctx.Rip = current_software_breakpoint_hit;
				SetThreadContext(hThread, &ctx);
				CloseHandle(hThread);
				return true;
			}
			return false;
		}

		bool has_exception() {
			if (debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
				return true;
			return false;
		}

		void exception_unhandled() {
			continue_status = DBG_EXCEPTION_NOT_HANDLED;
		}

		void continue_debug() {
			ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status);
		}

		DEBUG_EVENT wait_for_debug_event() {
			if (WaitForDebugEvent(&debug_event, INFINITE) == 0)
				detach();
			if (debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
				detach();
			return debug_event;
		}

		std::optional<CONTEXT> get_context() {
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debug_event.dwThreadId);
			if (hThread) {
				CONTEXT ctx = { 0 };
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(hThread, &ctx);
				return ctx;
			}
			return std::nullopt;
		}

		bool set_context(CONTEXT context) {
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debug_event.dwThreadId);
			if (hThread) {
				SetThreadContext(hThread, &context);
				return true;
			}
			return false;
		}
	};

}