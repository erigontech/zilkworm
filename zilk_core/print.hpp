
#pragma once
#ifdef SP1
#include "sp1_syscalls.hpp"
#elif defined(QEMU_DEBUG)
#include "semihosting.hpp"
#else
#include <iostream>
inline void sys_println(const char* msg) {
    std::cout << "stdout: " << msg << std::endl;
}
inline void sys_print(const char* msg) {
    std::cout << "stdout: " << msg;
}

[[noreturn]] inline void syscall_halt(uint8_t exit_code) {
    std::exit(exit_code);
}

#endif
