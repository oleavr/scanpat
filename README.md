# scanpat

Tool for generating [Frida](https://frida.re) `Memory.scan()` compatible
instruction search patterns. Powered by [r2](https://rada.re).

## Examples

```sh
$ ./scanpat.py arm.ks:64 'sub sp, sp, $imm'
ff 03 00 d1 : ff 03 e0 ff
$ ./scanpat.py arm.ks:64 'csel x21, $reg, x4, eq'
15 00 84 9a : 1f fc ff ff
$ ./scanpat.py x86.ks:64 'xor $reg, $reg'
31 c0 : ff c0
```

These examples use r2's Keystone plugin, which is recommended for higher
quality output: we bombard r2 with operands, some of which may not be
valid for a given instruction.
