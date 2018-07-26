when defined(windows):
  const libname = "unicorn.dll"
else:
  const libname = "libunicorn.so"

type
  Architecture* {.pure.} = enum
    ARM = 1,
    ARM64,
    MIPS,
    X86,
    PPC,
    SPARC,
    M68K,
    MAX

  UcError* {.pure.} = enum
    OK = 0,
    NOMEM,
    ARCH,
    HANDLE,
    MODE,
    VERSION,
    READ_UNMAPPED,
    WRITE_UNMAPPED,
    FETCH_UNMAPPED,
    HOOK,
    INSN_INVALID,
    MAP,
    WRITE_PROT,
    READ_PROT,
    FETCH_PROT,
    ARG,
    READ_UNALIGNED,
    WRITE_UNALIGNED,
    FETCH_UNALIGNED,
    HOOK_EXIST,
    RESOURCE,
    EXCEPTION
  
  MemAccess* {.pure.} = enum
    READ = 16,
    WRITE,
    FETCH,
    READ_UNMAPPED,
    WRITE_UNMAPPED,
    FETCH_UNMAPPED,
    WRITE_PROT,
    READ_PROT,
    FETCH_PROT,
    READ_AFTER
  
  MemProt* {.pure.} = enum
    NONE = 0,
    READ = 1,
    WRITE = 2,
    EXEC = 4,
    ALL = 7
  
  HookType* {.pure.} = enum
    INTR = 1 shl 0,
    INSN = 1 shl 1,
    CODE = 1 shl 2,
    BLOCK = 1 shl 3,
    MEM_READ_UNMAPPED = 1 shl 4,
    MEM_WRITE_UNMAPPED = 1 shl 5,
    MEM_FETCH_UNMAPPED = 1 shl 6,
    MEM_READ_PROT = 1 shl 7,
    MEM_WRITE_PROT = 1 shl 8,
    MEM_FETCH_PROT = 1 shl 9,
    MEM_READ = 1 shl 10,
    MEM_WRITE = 1 shl 11,
    MEM_FETCH = 1 shl 12,
    MEM_READ_AFTER = 1 shl 13,
  
  UcEngine* = pointer
  UcHook* =  csize

const
  UC_MODE_LITTLE_ENDIAN* = 0
  UC_MODE_ARM* = 0
  UC_MODE_BIG_ENDIAN* = 1 shl 30
  UC_MODE_THUMB* = 1 shl 4
  UC_MODE_MCLASS* = 1 shl 5
  UC_MODE_V8* = 1 shl 6
  UC_MODE_MICRO* = 1 shl 4
  UC_MODE_MIPS3* = 1 shl 5
  UC_MODE_MIPS32R6* = 1 shl 6
  UC_MODE_MIPS32* = 1 shl 2
  UC_MODE_MIPS64* = 1 shl 3
  UC_MODE_16* = 1 shl 1
  UC_MODE_32* = 1 shl 2
  UC_MODE_64* = 1 shl 3
  UC_MODE_PPC32* = 1 shl 2
  UC_MODE_PPC64* = 1 shl 3
  UC_MODE_QPX* = 1 shl 4
  UC_MODE_SPARC32* = 1 shl 2
  UC_MODE_SPARC64* = 1 shl 3
  UC_MODE_V9* = 1 shl 4

template genEnumFlags(obj: untyped): untyped =
  proc `or`*(a, b: obj): obj =
    (a.uint32 or b.uint32).obj

genEnumFlags(MemProt)
genEnumFlags(MemAccess)
genEnumFlags(HookType)

# Now the raw unicorn api
proc uc_version*(major: ptr cuint, minor: ptr cuint): cuint {.cdecl, importc, dynlib: libname .}
proc uc_arch_supported*(arch: Architecture): bool {.cdecl, importc, dynlib: libname .}
proc uc_open*(arch: Architecture, mode: uint, engine: ptr UcEngine): UcError {.cdecl, importc, dynlib: libname .}
proc uc_close*(engine: UcEngine): UcError {.cdecl, importc, dynlib: libname .}
proc uc_strerror*(error: UcError): cstring {.cdecl, importc, dynlib: libname .}
proc uc_reg_write*(engine: UcEngine, reg_id: cint, target: pointer): UcError {.cdecl, importc, dynlib: libname .}
proc uc_reg_read*(engine: UcEngine, reg_id: cint, value: pointer): UcError {.cdecl, importc, dynlib: libname .}
proc uc_mem_write*(engine: UcEngine, address: uint64, buffer: cstring, size: csize): UcError {.cdecl, importc, dynlib: libname .}
proc uc_mem_read*(engine: UcEngine, address: uint64, buffer: pointer, size: csize): UcError {.cdecl, importc, dynlib: libname .}
proc uc_emu_start*(engine: UcEngine, start: uint64, stop: uint64, timeout: uint64, count: uint64): UcError {.cdecl, importc, dynlib: libname .}
proc uc_emu_stop*(engine: UcEngine): UcError {.cdecl, importc, dynlib: libname .}
proc uc_hook_add*(engine: UcEngine, hook: ptr UcHook, hook_type: HookType, callback: pointer, start: uint64, stop: uint64): UcError {.cdecl, importc, dynlib: libname .}
proc uc_hook_del*(engine: UcEngine, hook: UcHook): UcError {.cdecl, importc, dynlib: libname .}
proc uc_mem_map*(engine: UcEngine, address: uint64, size: csize, perms: uint32): UcError {.cdecl, importc, dynlib: libname .}
proc uc_mem_map_ptr*(engine: UcEngine, address: uint64, size: csize, perms: uint32, mem: pointer): UcError {.cdecl, importc, dynlib: libname .}
proc uc_mem_unmap*(engine: UcEngine, address: uint64, size: csize): UcError {.cdecl, importc, dynlib: libname .}
proc uc_mem_protect*(engine: UcEngine, address: uint64, size: csize, perms: uint32): UcError {.cdecl, importc, dynlib: libname .}

type
  UnicornEngine* = ref object of RootObj
    engine*: UcEngine

  UnicornException* = object of Exception

# handle exceptions, returning the error message
template raiseOnError(code: UcError) =
  if code != UcError.OK:
    raise newException(UnicornException, $uc_strerror(code))

proc newUnicornEngine*(arch: Architecture, mode: uint): UnicornEngine =
  new(result)
  uc_open(arch, mode, addr result.engine).raiseOnError()

proc close*(uc: UnicornEngine) =
  uc_close(uc.engine).raiseOnError()

# reg write
proc regWrite[T](uc: UnicornEngine, reg_id: cint, target: T) =
  var numCopy = target
  uc_reg_write(uc.engine, reg_id, addr numCopy).raiseOnError()

proc regWrite8*(uc: UnicornEngine, reg_id: cint, target: uint8) =
  regWrite[uint8](uc, reg_id, target)

proc regWrite16*(uc: UnicornEngine, reg_id: cint, target: uint16) =
  regWrite[uint16](uc, reg_id, target)

proc regWrite32*(uc: UnicornEngine, reg_id: cint, target: uint32) =
  regWrite[uint32](uc, reg_id, target)

proc regWrite64*(uc: UnicornEngine, reg_id: cint, target: uint64) =
  regWrite[uint64](uc, reg_id, target)

# dunno why I can't call the function with the <object>.regRead[<type>](args...) syntax
# to be able to use the object syntax we have to write every width
proc regRead[T](uc: UnicornEngine, reg_id: cint): T =
  uc_reg_read(uc.engine, reg_id, addr result).raiseOnError()

proc regRead8*(uc: UnicornEngine, reg_id: cint): uint8 =
  result = regRead[uint8](uc, reg_id)

proc regRead16*(uc: UnicornEngine, reg_id: cint): uint16 =
  result = regRead[uint16](uc, reg_id)

proc regRead32*(uc: UnicornEngine, reg_id: cint): uint32 =
  result = regRead[uint32](uc, reg_id)

proc regRead64*(uc: UnicornEngine, reg_id: cint): uint64 =
  result = regRead[uint64](uc, reg_id)

# memory functions
proc memMap*(uc: UnicornEngine, address: uint64, size: csize, perms: MemProt) =
  uc_mem_map(uc.engine, address, size, perms.uint32).raiseOnError()

proc memUnmap*(uc: UnicornEngine, address: uint64, size: csize) =
  uc_mem_unmap(uc.engine, address, size).raiseOnError()

proc memWrite*(uc: UnicornEngine, address: uint64, data: string) =
  uc_mem_write(uc.engine, address, data, len(data)).raiseOnError()

proc memRead*(uc: UnicornEngine, address: uint64, len: csize): string =
  result = newString(len)
  uc_mem_read(uc.engine, address, addr result[0], len).raiseOnError()

proc memProtect*(uc: UnicornEngine, address: uint64, size: csize, prot: MemProt) =
  uc_mem_protect(uc.engine, address, size, prot.uint32).raiseOnError()

proc emuStart*(uc: UnicornEngine, start: uint64, stop: uint64, timeout: uint64, count: uint64) =
  uc_emu_start(uc.engine, start, stop, timeout, count).raiseOnError()