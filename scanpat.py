#!/usr/bin/env python3

import r2pipe
import re
import sys


VARIABLE_PATTERN = re.compile(r"\$(reg|nreg|lreg|hreg|imm)\b")

X86_GPR_NAMES = [
    "eax",
    "ecx",
    "edx",
    "ebx",
    "esp",
    "ebp",
    "esi",
    "edi",

    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rsp",
    "rbp",
    "rsi",
    "rdi",

    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
]

r2 = None


def generate_pattern(spec, assembler):
    global r2
    if r2 is None:
        r2 = r2pipe.open("-", flags=["-2"])

    if assembler.startswith("arm") and assembler.endswith(":16"):
        reg_handler = (generate_register_name_arm, (0, 15))
        nreg_handler = reg_handler
        lreg_handler = (generate_register_name_arm, (0, 8))
        hreg_handler = (generate_register_name_arm, (8, 16))
    elif assembler.startswith("arm") and assembler.endswith(":64"):
        reg_handler = (generate_register_name_arm64, (0, 32))
        nreg_handler = (generate_narrow_register_name_arm64, (0, 32))
        lreg_handler = reg_handler
        hreg_handler = reg_handler
    else:
        reg_handler = (generate_register_name_x86, (0, len(X86_GPR_NAMES)))
        nreg_handler = (generate_register_name_x86, (0, 8))
        lreg_handler = reg_handler
        hreg_handler = reg_handler

    compiled_spec = []
    start = 0
    for m in VARIABLE_PATTERN.finditer(spec):
        kind = m.group(1)
        end, next_start = m.span()

        text_before = spec[start:end]

        if kind == 'reg':
            handler = reg_handler
        elif kind == 'nreg':
            handler = nreg_handler
        elif kind == 'lreg':
            handler = lreg_handler
        elif kind == 'hreg':
            handler = hreg_handler
        elif kind == 'imm':
            handler = (generate_immediate, (0, 512))

        compiled_spec += [text_before, handler]

        start = next_start
    text_remaining = spec[start:]
    compiled_spec.append(text_remaining)

    expressions = set()
    current_variable_index = 0
    for current_part in compiled_spec:
        if isinstance(current_part, tuple):
            prefix_parts = []
            suffix_parts = []
            for i, part in enumerate(compiled_spec):
                if isinstance(part, tuple):
                    if i == current_variable_index:
                        continue
                    generate, (start, end) = part
                    part = generate(start)
                if i < current_variable_index:
                    prefix_parts.append(part)
                else:
                    suffix_parts.append(part)

            prefix = "".join(prefix_parts)
            suffix = "".join(suffix_parts)

            generate, (start, end) = current_part
            for val in range(start, end):
                expressions.add("".join([prefix, generate(val), suffix]))

        current_variable_index += 1

    if len(expressions) == 0:
        expressions = ["".join(compiled_spec)]

    example = None
    permutations = []
    pattern_width = None
    for expression in expressions:
        code = r2.cmd(f"pa {expression} @a:{assembler}").rstrip()
        if code == "":
            continue

        width = int(len(code) / 2)
        if pattern_width is None:
            pattern_width = width
        elif width != pattern_width:
            raise Exception("Unsupported spec; generates multiple instruction widths")

        values = []
        for i in range(0, len(code), 2):
            byte = int(code[i:i + 2], 16)
            values.append(byte)

        if example is None:
            example = " ".join([format(byte, "02x") for byte in values])

        permutation = []
        for byte in values:
            bits = [int(c) for c in format(byte, "08b")]
            permutation.append(bits)
        permutations.append(permutation)

    if len(permutations) == 0:
        raise Exception("Unable to assemble; missing plugin?")

    mask_pieces = []
    for group in range(pattern_width):
        bitmask = ""
        for bit in range(8):
            values = set([p[group][bit] for p in permutations])
            bitmask += "1" if len(values) == 1 else "0"
        mask_pieces.append(format(int(bitmask, 2), "02x"))
    mask = " ".join(mask_pieces)

    return f"{example} : {mask}"


def generate_register_name_arm(offset):
    return f"r{offset}"


def generate_register_name_arm64(offset):
    return f"x{offset}"


def generate_narrow_register_name_arm64(offset):
    return f"w{offset}"


def generate_register_name_x86(offset):
    return X86_GPR_NAMES[offset]


def generate_immediate(val):
    return str(val)


if __name__ == '__main__':
    assembler, spec = sys.argv[1:3]
    pattern = generate_pattern(spec, assembler)
    print(pattern)
