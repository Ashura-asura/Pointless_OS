OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

PHDRS
{
  text   PT_LOAD FLAGS(5); /* R + X */
  data   PT_LOAD FLAGS(6); /* R + W */
}

SECTIONS
{
  . = 0x100000;
  _kernel_base = .;

  .text : ALIGN(4K) {
    _text_start = .;
    *(.text .text.*)
    *(.rodata .rodata.*)
    _text_end = .;
  } :text

  . = ALIGN(4K);

  .rodata : ALIGN(4K) {
    *(.rodata .rodata.*)
  } :text

  . = ALIGN(4K);

  .data : ALIGN(4K) {
    *(.data .data.*)
  } :data

  . = ALIGN(4K);

  .bss : ALIGN(4K) {
    __bss_start = .;
    *(.bss .bss.*)
    *(COMMON)
    __bss_end = .;
  } :data

  /DISCARD/ : {
    *(.comment)
    *(.note*)
    *(.eh_frame*)
  }
}
