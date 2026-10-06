PROVIDE(_stext = ORIGIN(REGION_TEXT));
PROVIDE(_rom_size = LENGTH(ROM));
PROVIDE(_max_hart_id = 0);
PROVIDE(_hart_stack_size = 64M);
PROVIDE(_heap_size = 768M);

/*
PROVIDE(UserSoft = DefaultHandler);
PROVIDE(SupervisorSoft = DefaultHandler);
PROVIDE(MachineSoft = DefaultHandler);
PROVIDE(UserTimer = DefaultHandler);
PROVIDE(SupervisorTimer = DefaultHandler);
PROVIDE(MachineTimer = DefaultHandler);
PROVIDE(UserExternal = DefaultHandler);
PROVIDE(SupervisorExternal = DefaultHandler);
PROVIDE(MachineExternal = DefaultHandler);

PROVIDE(DefaultHandler = DefaultInterruptHandler);
PROVIDE(ExceptionHandler = DefaultExceptionHandler);
*/

/* # Pre-initialization function */
/* If the user overrides this using the `#[pre_init]` attribute or by creating a `__pre_init` function,
   then the function this points to will be called before the RAM is initialized. */
PROVIDE(__pre_init = default_pre_init);

/* A PAC/HAL defined routine that should initialize custom interrupt controller if needed. */
/*
PROVIDE(_setup_interrupts = default_setup_interrupts);
*/


/* # Start trap function override
  By default uses the riscv crates default trap handler
  but by providing the `_start_trap` symbol external crates can override.
*/
PROVIDE(_start_trap = default_start_trap);
PROVIDE(_machine_start_trap = machine_default_start_trap);

PHDRS
{
  text PT_LOAD;
  rodata PT_LOAD;
  data PT_LOAD;
  bss PT_LOAD;
}

SECTIONS
{
  .text.dummy (NOLOAD) :
  {
    /* This section is intended to make _stext address work */
    . = ABSOLUTE(_stext);
  } > REGION_TEXT AT > REGION_TEXT :text

  .text _stext : ALIGN(4096)
  {
    /* Put reset handler first in .text section so it ends up as the entry */
    /* point of the program. */
    KEEP(*(.init));
    KEEP(*(.init.rust));
    . = ALIGN(4);
    *(.trap);
    *(.trap.rust);

    *(.text .text.*);
  } > REGION_TEXT AT > REGION_TEXT :text

  /* fictitious region that represents the memory available for the stack */
  .stack ORIGIN(REGION_STACK) (NOLOAD) : ALIGN(4096)
  {
    _estack = .;
    . += (_max_hart_id + 1) * _hart_stack_size;
    . = ALIGN(4);
    _sstack = .;
  } > REGION_STACK

  .rodata : ALIGN(32)
  {
    _sirodata = LOADADDR(.rodata);
    _srodata = .;

    /* The gp window. ld rewrites an auipc+addi/lw/sw pair to a single gp-relative addi/lw/sw
       when the target lies within the reach of gp's 12-bit offset, less this output section's
       alignment (here 256, from the keccak buffer) and the object's size. The objects with the
       most executed address formations are gathered on both sides of __global_pointer$; below
       it the farthest come first. */
    *(.rodata._ZN8silkworm10kEmptyHashE)
    *(.rodata._ZN6evmone6crypto9secp256k112_GLOBAL__N_1L6FP_ONEE)
    *(.rodata._ZN6evmone6crypto5bn2549Fq6Config3ksiE)
    *(.rodata._ZZNKSt8__detail20_Prime_rehash_policy11_M_next_bktEjE10__fast_bkt)
    *(.rodata._ZN6evmone6crypto9secp256k15Curve2X1E .rodata._ZN6evmone6crypto9secp256k15Curve2X2E)
    *(.rodata._ZN6evmone6crypto9secp256k15Curve2Y2E .rodata._ZN6evmone6crypto9secp256k15Curve8MINUS_Y1E)
    *(.rodata.*secp256k1*L4wnafILj5EaEEjPT0_PKmE8DEBRUIJN)
    *(.rodata.*decomposeINS0_9secp256k15Curve*E3DET .rodata.*decomposeINS0_9secp256k15Curve*E12BARRETT_M_LO)
    *(.rodata._ZZN4evmc4Host13get_interfaceEvE9interface)
    *(.bss._ZZN8silkworm6endian14to_big_compactERKN4intx4uintILj256EEEE7full_be)
    *(.rodata._bls_np_hi)
    *(.rodata.*decode_node*12kAllHashLens)
    *(.rodata.memset_zeros)
    *(.sbss._ZZN8silkworm6endian14to_big_compactEyE7full_be)
    *(.sbss.allocated_bytes)
    *(.rodata._ZN6evmone6crypto3ecc12FieldElementINS0_9secp256k15Curve6FrSpecEE2FpE)
    *(.rodata._ZN4intx8internal5div3214clz_byte_tableE)
    *(.rodata.__clz_tab)
    . = ALIGN(256);
    __global_pointer$ = .;
    *(.bss.buf)
    *(.rodata._ZN6evmone6crypto3ecc12FieldElementINS0_9secp256k15Curve6FpSpecEE2FpE)
    *(.rodata.*dispatch_cgoto*11push1_table)
    *(.rodata._ZN6evmone6crypto3ecc12FieldElementINS0_5bn2545Curve6FpSpecEE2FpE)
    *(.rodata._bls_p_lo)
    *(.rodata._bls_np_lo)
    *(.rodata._bls_p_hi)
    ASSERT(. <= __global_pointer$ + 2048 - 256, "the gp window overflows above gp");

    *(.srodata .srodata.*);
    *(.rodata .rodata.*);

    /* 32-byte align the end for BigInt CSR compatibility. */
    . = ALIGN(32);

    _erodata = .;
  } > REGION_RODATA AT > REGION_RODATAINIT :rodata

  /* C++ global constructors / destructors (init_array style).
     Read-only function-pointer arrays kept directly in ROM (VMA = LMA)
     so they are available immediately — no copy required. */
  .preinit_array : ALIGN(4)
  {
    PROVIDE_HIDDEN(__preinit_array_start = .);
    KEEP(*(.preinit_array))
    PROVIDE_HIDDEN(__preinit_array_end = .);
  } > REGION_TEXT AT > REGION_TEXT :text

  .init_array : ALIGN(4)
  {
    PROVIDE_HIDDEN(__init_array_start = .);
    KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
    KEEP(*(.init_array EXCLUDE_FILE(*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o) .ctors))
    PROVIDE_HIDDEN(__init_array_end = .);
  } > REGION_TEXT AT > REGION_TEXT :text

  .fini_array : ALIGN(4)
  {
    PROVIDE_HIDDEN(__fini_array_start = .);
    KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
    KEEP(*(.fini_array EXCLUDE_FILE(*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o) .dtors))
    PROVIDE_HIDDEN(__fini_array_end = .);
  } > REGION_TEXT AT > REGION_TEXT :text

  .data : ALIGN(4096)
  {
    _sidata = LOADADDR(.data);
    _sdata = .;
    *(.sdata .sdata.* .sdata2 .sdata2.*);
    *(.data .data.*);
    /* GOT entries – some pre-built libraries are compiled with -fPIC */
    *(.got .got.*);
    . = ALIGN(4);
    _edata = .;
  } > REGION_DATA AT > REGION_DATAINIT :data

  .bss (NOLOAD) : ALIGN(4096)
  {
    _sbss = .;
    *(.sbss .sbss.* .bss .bss.*);
    . = ALIGN(4);
    _ebss = .;
  } > REGION_BSS AT > REGION_BSS :bss

  /* Newlib's _sbrk needs the `end` symbol (end of BSS = start of heap area) */
  PROVIDE(end = _ebss);

  /* fictitious region that represents the memory available for the heap */
  .heap (NOLOAD) : ALIGN(2097152)
  {
    _sheap = .;
    . += _heap_size;
    . = ALIGN(2097152);
    _eheap = .;
  } > REGION_HEAP

  .eh_frame (INFO) : { KEEP(*(.eh_frame)) }
  .eh_frame_hdr (INFO) : { *(.eh_frame_hdr) }

  /* Discard C++ exception tables – we build with -fno-exceptions */
  /DISCARD/ :
  {
    *(.gcc_except_table .gcc_except_table.*)
  }
}

/* Do not exceed this mark in the error messages above                                    | */
ASSERT(ORIGIN(REGION_TEXT) % 4 == 0, "
ERROR(riscv-rt): the start of the REGION_TEXT must be 4-byte aligned");

ASSERT(ORIGIN(REGION_RODATAINIT) % 4 == 0, "
ERROR(riscv-rt): the start of the REGION_RODATAINIT must be 4-byte aligned");

ASSERT(ORIGIN(REGION_RODATA) % 4 == 0, "
ERROR(riscv-rt): the start of the REGION_RODATA must be 4-byte aligned");

ASSERT(ORIGIN(REGION_DATAINIT) % 4 == 0, "
ERROR(riscv-rt): the start of the REGION_DATAINIT must be 4-byte aligned");

ASSERT(ORIGIN(REGION_DATA) % 4 == 0, "
ERROR(riscv-rt): the start of the REGION_DATA must be 4-byte aligned");

ASSERT(ORIGIN(REGION_HEAP) % 4 == 0, "
ERROR(riscv-rt): the start of the REGION_HEAP must be 4-byte aligned");

ASSERT(ORIGIN(REGION_TEXT) % 4 == 0, "
ERROR(riscv-rt): the start of the REGION_TEXT must be 4-byte aligned");

ASSERT(ORIGIN(REGION_STACK) % 4 == 0, "
ERROR(riscv-rt): the start of the REGION_STACK must be 4-byte aligned");

ASSERT(_stext % 4 == 0, "
ERROR(riscv-rt): `_stext` must be 4-byte aligned");

ASSERT(_srodata % 4 == 0 && _erodata % 4 == 0, "
BUG(riscv-rt): .rodata is not 4-byte aligned");

ASSERT(_sirodata % 4 == 0, "
BUG(riscv-rt): the LMA of .rodata is not 4-byte aligned");

ASSERT(_sdata % 4 == 0 && _edata % 4 == 0, "
BUG(riscv-rt): .data is not 4-byte aligned");

ASSERT(_sidata % 4 == 0, "
BUG(riscv-rt): the LMA of .data is not 4-byte aligned");

ASSERT(_sbss % 4 == 0 && _ebss % 4 == 0, "
BUG(riscv-rt): .bss is not 4-byte aligned");

ASSERT(_sheap % 4 == 0, "
BUG(riscv-rt): start of .heap is not 4-byte aligned");

ASSERT(_stext + SIZEOF(.text) < ORIGIN(REGION_TEXT) + LENGTH(REGION_TEXT), "
ERROR(riscv-rt): The .text section must be placed inside the REGION_TEXT region.
Set _stext to an address smaller than 'ORIGIN(REGION_TEXT) + LENGTH(REGION_TEXT)'");

/* ASSERT(_sirodata + SIZEOF(.rodata) < ORIGIN(REGION_RODATAINIT) + LENGTH(REGION_RODATAINIT), "
ERROR(riscv-rt): The init data for .rodata section must be placed inside the REGION_RODATAINIT region.
Set _sirodata to an address smaller than 'ORIGIN(REGION_RODATAINIT) + LENGTH(REGION_RODATAINIT)'"); */

ASSERT(_sidata + SIZEOF(.data) < ORIGIN(REGION_DATAINIT) + LENGTH(REGION_DATAINIT), "
ERROR(riscv-rt): The init data for .data section must be placed inside the REGION_DATAINIT region.
Set _sidata to an address smaller than 'ORIGIN(REGION_DATAINIT) + LENGTH(REGION_DATAINIT)'");

ASSERT(SIZEOF(.stack) >= (_max_hart_id + 1) * _hart_stack_size, "
ERROR(riscv-rt): .stack section is too small for allocating stacks for all the harts.
Consider changing `_max_hart_id` or `_hart_stack_size`.");

/* Do not exceed this mark in the error messages above                                    | */