// Copyright The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
#pragma once
#ifdef SP1
#include <sp1_syscalls.hpp>
#elif defined(QEMU_DEBUG)
#include <semihosting.hpp>
#elif defined(AIRBENDER)
#include <airbender_csr.hpp>
#else
#include <iostream>
#include <string_view>
inline void sys_println(const char* msg) {
    std::cout << "stdout: " << msg << std::endl;
}
inline void sys_print(const char* msg) {
    std::cout << "stdout: " << msg;
}
inline void sys_println(std::string_view msg) {
    std::cout << "stdout: " << msg << std::endl;
}
inline void sys_print(std::string_view msg) {
    std::cout << "stdout: " << msg;
}

[[noreturn]] inline void syscall_halt(uint8_t exit_code) {
    std::exit(exit_code);
}

#endif
