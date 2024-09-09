#include "include/debug_util.h"

int main() {
	DEBUG_UTIL::DBG debugger("ANYPROCESS.exe");
	
	debugger.wait_for_process(nullptr, 10);
	debugger.wait_for_module("MODULE_X", 10);

	auto license_address = debugger.find_signature("MODULE_X", "\x89\x68\x18", "xxx");

	debugger.attach();

	debugger.set_hardware_breakpoint(license_address, DEBUG_UTIL::HWBP::HARDWARE_BREAKPOINT_1);

	while (debugger.is_attached()) {
		debugger.wait_for_debug_event();
		if (debugger.has_exception()) {
			if (debugger.has_hardware_breakpoint_hit(DEBUG_UTIL::HWBP::HARDWARE_BREAKPOINT_1)) {
				auto context = debugger.get_context();
				if (context.has_value()) {
					context.value().Rbp = 1;
				}
				DEBUG_UTIL::DBG::continue_after_hardware_breakpoint_hit(context.value());
				debugger.set_context(context.value());
				debugger.hardware_breakpoint_handled();
			}
			else
				debugger.exception_unhandled();
		}
		debugger.continue_debug();
	}

}