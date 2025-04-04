MEMORY {
  dram_space (rwx) : ORIGIN = 0x20400000, LENGTH = 128
}

SECTIONS {
  .text : {
    jump.o(.text.bios)
  } > dram_space
}
