ENTRY(_start)

SECTIONS
{
    . = 0x1000;

    .text : {
        KEEP(*(.text._start))
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.eh_frame*)
        *(.comment)
        *(.note*)
        *(.dyn*)
        *(.gnu*)
        *(.hash)
        *(.dynamic)
        *(.interp)
        *(.rela*)
        *(.rel*)
    }
}
