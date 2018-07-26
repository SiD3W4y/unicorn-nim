# unicorn-nim
This project is a simple and not feature complete wrapper around Unicorn.

# TODO
- Add Hooks

## Example code

```nim
import unicorn
import unicorn.arm_const

var engine = newUnicornEngine(Architecture.ARM, UC_MODE_ARM)

# create memory region
engine.memMap(0x0, 0x1000, MemProt.ALL)

# copy code into region
engine.memWrite(0x0, "\x90\x01\x00\xe0") # mul r0, r0, r1

# sets the registers
engine.regWrite32(UC_ARM_REG_R0, 2)
engine.regWrite32(UC_ARM_REG_R1, 33)

# emulate a single instruction
# arg 1 -> start (0x0)
# arg 2 -> stop (0x1000)
# arg 3 -> timeout (0x0)
# arg 4 -> number of instructions to emulate (0x1)
engine.emuStart(0x0, 0x1000, 0, 1)

# should display 66
echo "result = " & $engine.regRead32(UC_ARM_REG_R0)
```