OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

PHDRS
{
  text PT_LOAD FLAGS(5);   /* R + X, single segment */
}

SECTIONS
{
  . = 0x400000;
  .text : {
    *(.text*)
    *(.rodata*)
  } :text
  . = ALIGN(16);
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.rela.*) }
}
