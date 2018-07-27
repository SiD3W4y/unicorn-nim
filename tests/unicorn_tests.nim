import ../src/unicorn
import ../src/unicorn/x86_const
import ../src/unicorn/arm_const

proc codeHook(uc: UnicornEngine, address: uint64, size: uint32) {.cdecl.} =
  echo "Tracing instruction of size -> " & $size

proc testMem() =
  echo ">> Testing memory"

  var engine = newUnicornEngine(Architecture.X86, UC_MODE_32)
  engine.memMap(0x0, 0x1000, MemProt.READ or MemProt.WRITE or MemProt.EXEC)
  engine.memWrite(0x0, "ABCD")
  assert(engine.memRead(0x0, 4) == "ABCD")

proc testX8632() =
  echo ">> Testing x86_32"
  var engine = newUnicornEngine(Architecture.X86, UC_MODE_32)

  # testing registers
  engine.regWrite32(UC_X86_REG_EAX, 0x1337)
  engine.regWrite32(UC_X86_REG_EBP, 0x7fff)
  assert(engine.regRead32(UC_X86_REG_EAX) == 0x1337)
  assert(engine.regRead32(UC_X86_REG_EBP) == 0x7fff)

  # mapping memory for emulation
  engine.memMap(0x0, 0x2000, MemProt.READ or MemProt.WRITE or MemProt.EXEC)

  # add a hook
  discard engine.hookCode(HookType.CODE, codeHook, 0, 0)

  engine.memWrite(0x0, "\x01\xD8") # add eax, ebx
  engine.regWrite32(UC_X86_REG_EAX, 22)
  engine.regWrite32(UC_X86_REG_EBX, 44)
  engine.emuStart(0x0, 0x1000, 0, 1) # emulate one instruction

  assert(engine.regRead32(UC_X86_REG_EAX) == 66)
  engine.close()

proc testARM() = 
  echo ">> Testing arm"
  var engine = newUnicornEngine(Architecture.ARM, UC_MODE_ARM)

  # testing registers
  engine.regWrite32(UC_ARM_REG_R0, 0x1337)
  engine.regWrite32(UC_ARM_REG_R1, 0x7fff)
  assert(engine.regRead32(UC_ARM_REG_R0) == 0x1337)
  assert(engine.regRead32(UC_ARM_REG_R1) == 0x7fff)

  engine.memMap(0x0, 0x1000, MemProt.ALL)

  # add a hook function
  discard engine.hookCode(HookType.CODE, codeHook, 0, 0)

  engine.memWrite(0x0, "\x90\x01\x00\xe0") # mul r0, r0, r1
  engine.regWrite32(UC_ARM_REG_R0, 2)
  engine.regWrite32(UC_ARM_REG_R1, 33)
  engine.emuStart(0x0, 0x1000, 0, 1)

  assert(engine.regRead32(UC_ARM_REG_R0) == 66)
  engine.close()

when(isMainModule):
  testMem()
  testX8632()
  testARM()