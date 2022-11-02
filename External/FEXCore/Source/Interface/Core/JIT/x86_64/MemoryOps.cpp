/*
$info$
tags: backend|x86-64
$end_info$
*/

#include "Interface/Core/CPUID.h"
#include "Interface/Core/JIT/x86_64/JITClass.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/IR/IR.h>
#include <FEXCore/Utils/LogManager.h>

#include <array>
#include <stddef.h>
#include <stdint.h>
#include <xbyak/xbyak.h>

namespace FEXCore::CPU {

#define DEF_OP(x) void X86JITCore::Op_##x(IR::IROp_Header *IROp, IR::NodeID Node)

DEF_OP(LoadContext) {
  const auto Op = IROp->C<IR::IROp_LoadContext>();
  const auto OpSize = IROp->Size;

  if (Op->Class == IR::GPRClass) {
    switch (OpSize) {
    case 1: {
      movzx(GetDst<RA_32>(Node), byte [STATE + Op->Offset]);
      break;
    }
    case 2: {
      movzx(GetDst<RA_32>(Node), word [STATE + Op->Offset]);
      break;
    }
    case 4: {
      mov(GetDst<RA_32>(Node), dword [STATE + Op->Offset]);
      break;
    }
    case 8: {
      mov(GetDst<RA_64>(Node), qword [STATE + Op->Offset]);
      break;
    }
    case 16: {
      LOGMAN_MSG_A_FMT("Invalid GPR load of size 16");
      break;
    }
    default:
      LOGMAN_MSG_A_FMT("Unhandled LoadContext size: {}", OpSize);
      break;
    }
  }
  else {
    const auto Dst = GetDst(Node);

    switch (OpSize) {
    case 1: {
      movzx(rax, byte [STATE + Op->Offset]);
      vmovq(Dst, rax);
      break;
    }
    case 2: {
      movzx(rax, word [STATE + Op->Offset]);
      vmovq(Dst, rax);
      break;
    }
    case 4: {
      vmovd(Dst, dword [STATE + Op->Offset]);
      break;
    }
    case 8: {
      vmovq(Dst, qword [STATE + Op->Offset]);
      break;
    }
    case 16: {
      if (Op->Offset % 16 == 0) {
        vmovaps(Dst, xword [STATE + Op->Offset]);
      } else {
        vmovups(Dst, xword [STATE + Op->Offset]);
      }
      break;
    }
    case 32: {
      if (Op->Offset % 32 == 0) {
        vmovaps(ToYMM(Dst), yword [STATE + Op->Offset]);
      } else {
        vmovups(ToYMM(Dst), yword [STATE + Op->Offset]);
      }
      break;
    }
    default:
      LOGMAN_MSG_A_FMT("Unhandled LoadContext size: {}", OpSize);
      break;
    }
  }
}

DEF_OP(StoreContext) {
  const auto Op = IROp->C<IR::IROp_StoreContext>();
  const auto OpSize = IROp->Size;

  if (Op->Class == IR::GPRClass) {
    switch (OpSize) {
    case 1: {
      mov(byte [STATE + Op->Offset], GetSrc<RA_8>(Op->Value.ID()));
      break;
    }
    case 2: {
      mov(word [STATE + Op->Offset], GetSrc<RA_16>(Op->Value.ID()));
      break;
    }
    case 4: {
      mov(dword [STATE + Op->Offset], GetSrc<RA_32>(Op->Value.ID()));
      break;
    }
    case 8: {
      mov(qword [STATE + Op->Offset], GetSrc<RA_64>(Op->Value.ID()));
      break;
    }
    case 16: {
      LOGMAN_MSG_A_FMT("Invalid store size of 16");
      break;
    }
    default:
      LOGMAN_MSG_A_FMT("Unhandled StoreContext size: {}", OpSize);
      break;
    }
  }
  else {
    const auto Value = GetSrc(Op->Value.ID());

    switch (OpSize) {
    case 1: {
      pextrb(byte [STATE + Op->Offset], Value, 0);
      break;
    }
    case 2: {
      pextrw(word [STATE + Op->Offset], Value, 0);
      break;
    }
    case 4: {
      vmovd(dword [STATE + Op->Offset], Value);
      break;
    }
    case 8: {
      vmovq(qword [STATE + Op->Offset], Value);
      break;
    }
    case 16: {
      if (Op->Offset % 16 == 0) {
        vmovaps(xword [STATE + Op->Offset], Value);
      } else {
        vmovups(xword [STATE + Op->Offset], Value);
      }
      break;
    }
    case 32: {
      if (Op->Offset % 32 == 0) {
        vmovaps(yword [STATE + Op->Offset], ToYMM(Value));
      } else {
        vmovups(yword [STATE + Op->Offset], ToYMM(Value));
      }
      break;
    }
    default:
      LOGMAN_MSG_A_FMT("Unhandled StoreContext size: {}", OpSize);
      break;
    }
  }
}

DEF_OP(LoadContextIndexed) {
  auto Op = IROp->C<IR::IROp_LoadContextIndexed>();
  size_t size = IROp->Size;
  Reg index = GetSrc<RA_64>(Op->Index.ID());

  if (Op->Class == IR::GPRClass) {
    switch (Op->Stride) {
    case 1:
    case 2:
    case 4:
    case 8: {
      lea(rax, dword [STATE + Op->BaseOffset]);
      switch (size) {
      case 1:
        movzx(GetDst<RA_32>(Node), byte [rax + index * Op->Stride]);
        break;
      case 2:
        movzx(GetDst<RA_32>(Node), word [rax + index * Op->Stride]);
        break;
      case 4:
        mov(GetDst<RA_32>(Node),  dword [rax + index * Op->Stride]);
        break;
      case 8:
        mov(GetDst<RA_64>(Node),  qword [rax + index * Op->Stride]);
        break;
      default:
        LOGMAN_MSG_A_FMT("Unhandled LoadContextIndexed size: {}", IROp->Size);
        break;
      }
      break;
    }
    case 16:
      LOGMAN_MSG_A_FMT("Invalid Class load of size 16");
      break;
    default:
      LOGMAN_MSG_A_FMT("Unhandled LoadContextIndexed stride: {}", Op->Stride);
      break;
    }
  }
  else {
    switch (Op->Stride) {
    case 1:
    case 2:
    case 4:
    case 8: {
      lea(rax, dword [STATE + Op->BaseOffset]);
      switch (size) {
      case 1:
        movzx(eax, byte [rax + index * Op->Stride]);
        vmovd(GetDst(Node), eax);
        break;
      case 2:
        movzx(eax, word [rax + index * Op->Stride]);
        vmovd(GetDst(Node), eax);
        break;
      case 4:
        vmovd(GetDst(Node),  dword [rax + index * Op->Stride]);
        break;
      case 8:
        vmovq(GetDst(Node),  qword [rax + index * Op->Stride]);
        break;
      default:
        LOGMAN_MSG_A_FMT("Unhandled LoadContextIndexed size: {}", IROp->Size);
        break;
      }
      break;
    }
    case 16: {
      mov(rax, index);
      shl(rax, 4);
      lea(rax, dword [rax + Op->BaseOffset]);
      switch (size) {
      case 1:
        pinsrb(GetDst(Node), byte [STATE + rax], 0);
        break;
      case 2:
        pinsrw(GetDst(Node), word [STATE + rax], 0);
        break;
      case 4:
        vmovd(GetDst(Node), dword [STATE + rax]);
        break;
      case 8:
        vmovq(GetDst(Node), qword [STATE + rax]);
        break;
      case 16:
        if (Op->BaseOffset % 16 == 0)
          movaps(GetDst(Node), xword [STATE + rax]);
        else
          movups(GetDst(Node), xword [STATE + rax]);
        break;
      default:
        LOGMAN_MSG_A_FMT("Unhandled LoadContextIndexed size: {}", IROp->Size);
        break;
      }
      break;
    }
    default:
      LOGMAN_MSG_A_FMT("Unhandled LoadContextIndexed stride: {}", Op->Stride);
      break;
    }
  }
}

DEF_OP(StoreContextIndexed) {
  const auto Op = IROp->C<IR::IROp_StoreContextIndexed>();
  const auto OpSize = IROp->Size;

  const Reg Index = GetSrc<RA_64>(Op->Index.ID());

  if (Op->Class == IR::GPRClass) {
    const auto Value = GetSrc<RA_64>(Op->Value.ID());
    lea(rax, dword [STATE + Op->BaseOffset]);

    switch (Op->Stride) {
    case 1:
    case 2:
    case 4:
    case 8: {
      if (!(OpSize == 1 || OpSize == 2 || OpSize == 4 || OpSize == 8)) {
        LOGMAN_MSG_A_FMT("Unhandled StoreContextIndexed size: {}", OpSize);
      }
      mov(AddressFrame(OpSize * 8) [rax + Index * Op->Stride], Value);
      break;
    }
    default:
      LOGMAN_MSG_A_FMT("Unhandled StoreContextIndexed stride: {}", Op->Stride);
      break;
    }
  }
  else {
    const auto Value = GetSrc(Op->Value.ID());
    switch (Op->Stride) {
    case 1:
    case 2:
    case 4:
    case 8: {
      lea(rax, dword [STATE + Op->BaseOffset]);
      switch (OpSize) {
      case 1:
        pextrb(AddressFrame(OpSize * 8) [rax + Index * Op->Stride], Value, 0);
        break;
      case 2:
        pextrw(AddressFrame(OpSize * 8) [rax + Index * Op->Stride], Value, 0);
        break;
      case 4:
        vmovd(AddressFrame(OpSize * 8) [rax + Index * Op->Stride], Value);
        break;
      case 8:
        vmovq(AddressFrame(OpSize * 8) [rax + Index * Op->Stride], Value);
        break;
      default:
        LOGMAN_MSG_A_FMT("Unhandled StoreContextIndexed size: {}", OpSize);
        break;
      }
      break;
    }
    case 16:
    case 32: {
      const auto Shift = Op->Stride == 16 ? 4 : 5;

      mov(rax, Index);
      shl(rax, Shift);
      lea(rax, dword [rax + Op->BaseOffset]);
      switch (OpSize) {
      case 1:
        pextrb(AddressFrame(OpSize * 8) [STATE + rax], Value, 0);
        break;
      case 2:
        pextrw(AddressFrame(OpSize * 8) [STATE + rax], Value, 0);
        break;
      case 4:
        vmovd(AddressFrame(OpSize * 8) [STATE + rax], Value);
        break;
      case 8:
        vmovq(AddressFrame(OpSize * 8) [STATE + rax], Value);
        break;
      case 16:
        if (Op->BaseOffset % 16 == 0) {
          vmovaps(xword [STATE + rax], Value);
        } else {
          vmovups(xword [STATE + rax], Value);
        }
        break;
      case 32:
        if (Op->BaseOffset % 32 == 0) {
          vmovaps(yword [STATE + rax], ToYMM(Value));
        } else {
          vmovups(yword [STATE + rax], ToYMM(Value));
        }
        break;
      default:
        LOGMAN_MSG_A_FMT("Unhandled StoreContextIndexed size: {}", OpSize);
        break;
      }
      break;
    }
    default:
      LOGMAN_MSG_A_FMT("Unhandled StoreContextIndexed stride: {}", Op->Stride);
      break;
    }
  }
}

DEF_OP(SpillRegister) {
  const auto Op = IROp->C<IR::IROp_SpillRegister>();
  const uint8_t OpSize = IROp->Size;
  const uint32_t SlotOffset = Op->Slot * MaxSpillSlotSize;

  if (Op->Class == FEXCore::IR::GPRClass) {
    switch (OpSize) {
      case 1: {
        mov(byte [rsp + SlotOffset], GetSrc<RA_8>(Op->Value.ID()));
        break;
      }
      case 2: {
        mov(word [rsp + SlotOffset], GetSrc<RA_16>(Op->Value.ID()));
        break;
      }
      case 4: {
        mov(dword [rsp + SlotOffset], GetSrc<RA_32>(Op->Value.ID()));
        break;
      }
      case 8: {
        mov(qword [rsp + SlotOffset], GetSrc<RA_64>(Op->Value.ID()));
        break;
      }
      default:
        LOGMAN_MSG_A_FMT("Unhandled SpillRegister size: {}", OpSize);
        break;
    }
  } else if (Op->Class == FEXCore::IR::FPRClass) {
    const auto Src = GetSrc(Op->Value.ID());

    switch (OpSize) {
      case 4: {
        movss(dword [rsp + SlotOffset], Src);
        break;
      }
      case 8: {
        movsd(qword [rsp + SlotOffset], Src);
        break;
      }
      case 16: {
        movaps(xword [rsp + SlotOffset], Src);
        break;
      }
      case 32: {
        vmovaps(yword [rsp + SlotOffset], ToYMM(Src));
        break;
      }
      default:
        LOGMAN_MSG_A_FMT("Unhandled SpillRegister size: {}", OpSize);
        break;
    }
  } else {
    LOGMAN_MSG_A_FMT("Unhandled SpillRegister class: {}", Op->Class.Val);
  }
}

DEF_OP(FillRegister) {
  const auto Op = IROp->C<IR::IROp_FillRegister>();
  const uint8_t OpSize = IROp->Size;
  const uint32_t SlotOffset = Op->Slot * MaxSpillSlotSize;

  if (Op->Class == FEXCore::IR::GPRClass) {
    switch (OpSize) {
      case 1: {
        movzx(GetDst<RA_32>(Node), byte [rsp + SlotOffset]);
        break;
      }
      case 2: {
        movzx(GetDst<RA_32>(Node), word [rsp + SlotOffset]);
        break;
      }
      case 4: {
        mov(GetDst<RA_32>(Node), dword [rsp + SlotOffset]);
        break;
      }
      case 8: {
        mov(GetDst<RA_64>(Node), qword [rsp + SlotOffset]);
        break;
      }
      default:
        LOGMAN_MSG_A_FMT("Unhandled FillRegister size: {}", OpSize);
        break;
    }
  } else if (Op->Class == FEXCore::IR::FPRClass) {
    const auto Dst = GetDst(Node);

    switch (OpSize) {
      case 4: {
        vmovss(Dst, dword [rsp + SlotOffset]);
        break;
      }
      case 8: {
        vmovsd(Dst, qword [rsp + SlotOffset]);
        break;
      }
      case 16: {
        vmovaps(Dst, xword [rsp + SlotOffset]);
        break;
      }
      case 32: {
        vmovaps(ToYMM(Dst), yword [rsp + SlotOffset]);
        break;
      }
      default:
        LOGMAN_MSG_A_FMT("Unhandled FillRegister size: {}", OpSize);
        break;
    }
  } else {
    LOGMAN_MSG_A_FMT("Unhandled FillRegister class: {}", Op->Class.Val);
  }
}

DEF_OP(LoadFlag) {
  auto Op = IROp->C<IR::IROp_LoadFlag>();

  auto Dst = GetDst<RA_64>(Node);
  movzx(Dst, byte [STATE + (offsetof(FEXCore::Core::CPUState, flags[0]) + Op->Flag)]);
}

DEF_OP(StoreFlag) {
  auto Op = IROp->C<IR::IROp_StoreFlag>();

  mov (rax, GetSrc<RA_64>(Op->Value.ID()));
  mov(byte [STATE + (offsetof(FEXCore::Core::CPUState, flags[0]) + Op->Flag)], al);
}

Xbyak::RegExp X86JITCore::GenerateModRM(Xbyak::Reg Base, IR::OrderedNodeWrapper Offset, IR::MemOffsetType OffsetType, uint8_t OffsetScale) const {
  if (Offset.IsInvalid()) {
    return Base;
  } else {
    if (OffsetScale != 1 && OffsetScale != 2 && OffsetScale != 4 && OffsetScale != 8) {
      LOGMAN_MSG_A_FMT("Unhandled GenerateModRM OffsetScale: {}", OffsetScale);
    }

    if (OffsetType != IR::MEM_OFFSET_SXTX) {
      LOGMAN_MSG_A_FMT("Unhandled GenerateModRM OffsetType: {}", OffsetType.Val);
    }

    uint64_t Const;
    if (IsInlineConstant(Offset, &Const)) {
      return Base + Const;
    } else {
      auto MemOffset = GetSrc<RA_64>(Offset.ID());

      return Base + MemOffset * OffsetScale;
    }
  }
}

DEF_OP(LoadMem) {
  const auto Op = IROp->C<IR::IROp_LoadMem>();
  const auto OpSize = IROp->Size;

  const Xbyak::Reg MemReg = GetSrc<RA_64>(Op->Addr.ID());
  const auto MemPtr = GenerateModRM(MemReg, Op->Offset, Op->OffsetType, Op->OffsetScale);

  if (Op->Class == IR::GPRClass) {
    const auto Dst = GetDst<RA_64>(Node);

    switch (OpSize) {
      case 1: {
        movzx(Dst, byte [MemPtr]);
        break;
      }
      case 2: {
        movzx(Dst, word [MemPtr]);
        break;
      }
      case 4: {
        mov(Dst.cvt32(), dword [MemPtr]);
        break;
      }
      case 8: {
        mov(Dst, qword [MemPtr]);
        break;
      }
      default:
        LOGMAN_MSG_A_FMT("Unhandled LoadMem size: {}", OpSize);
        break;
    }
  }
  else
  {
    const auto Dst = GetDst(Node);

    switch (OpSize) {
      case 1: {
        movzx(eax, byte [MemPtr]);
        vmovd(Dst, eax);
        break;
      }
      case 2: {
        movzx(eax, word [MemPtr]);
        vmovd(Dst, eax);
        break;
      }
      case 4: {
        vmovd(Dst, dword [MemPtr]);
        break;
      }
      case 8: {
        vmovq(Dst, qword [MemPtr]);
        break;
      }
      case 16: {
        vmovups(Dst, xword [MemPtr]);
        if (MemoryDebug) {
          movq(rcx, Dst);
        }
        break;
      }
      case 32: {
        vmovups(ToYMM(Dst), yword [MemPtr]);
        if (MemoryDebug) {
          movq(rcx, Dst);
        }
        break;
      }
      default:
        LOGMAN_MSG_A_FMT("Unhandled LoadMem size: {}", OpSize);
        break;
    }
  }
}

DEF_OP(StoreMem) {
  const auto Op = IROp->C<IR::IROp_StoreMem>();
  const auto OpSize = IROp->Size;

  const Xbyak::Reg MemReg = GetSrc<RA_64>(Op->Addr.ID());
  const auto MemPtr = GenerateModRM(MemReg, Op->Offset, Op->OffsetType, Op->OffsetScale);

  if (Op->Class == IR::GPRClass) {
    switch (OpSize) {
    case 1:
      mov(byte [MemPtr], GetSrc<RA_8>(Op->Value.ID()));
      break;
    case 2:
      mov(word [MemPtr], GetSrc<RA_16>(Op->Value.ID()));
      break;
    case 4:
      mov(dword [MemPtr], GetSrc<RA_32>(Op->Value.ID()));
      break;
    case 8:
      mov(qword [MemPtr], GetSrc<RA_64>(Op->Value.ID()));
      break;
    default:
      LOGMAN_MSG_A_FMT("Unhandled StoreMem size: {}", OpSize);
      break;
    }
  }
  else {
    const auto Value = GetSrc(Op->Value.ID());

    switch (OpSize) {
    case 1:
      pextrb(byte [MemPtr], Value, 0);
      break;
    case 2:
      pextrw(word [MemPtr], Value, 0);
      break;
    case 4:
      vmovd(dword [MemPtr], Value);
      break;
    case 8:
      vmovq(qword [MemPtr], Value);
      break;
    case 16:
      vmovups(xword [MemPtr], Value);
      break;
    case 32:
      vmovups(yword [MemPtr], ToYMM(Value));
      break;
    default:
      LOGMAN_MSG_A_FMT("Unhandled StoreMem size: {}", OpSize);
      break;
    }
  }
}

DEF_OP(VLoadMemElement) {
  LOGMAN_MSG_A_FMT("Unimplemented");
}

DEF_OP(VStoreMemElement) {
  LOGMAN_MSG_A_FMT("Unimplemented");
}

DEF_OP(CacheLineClear) {
  auto Op = IROp->C<IR::IROp_CacheLineClear>();

  Xbyak::Reg MemReg = GetSrc<RA_64>(Op->Addr.ID());

  clflush(ptr [MemReg]);
}

DEF_OP(CacheLineZero) {
  auto Op = IROp->C<IR::IROp_CacheLineZero>();

  Xbyak::Reg MemReg = GetSrc<RA_64>(Op->Addr.ID());

  // Align by cacheline
  mov (TMP1, CPUIDEmu::CACHELINE_SIZE - 1);
  andn(TMP1, TMP1, MemReg.cvt64());
  xor_(TMP2, TMP2);

  using DataType = uint64_t;
  // 64-byte cache line zero
  for (size_t i = 0; i < CPUIDEmu::CACHELINE_SIZE; i += sizeof(DataType)) {
    mov (qword [TMP1 + i], TMP2);
  }
}

#undef DEF_OP
void X86JITCore::RegisterMemoryHandlers() {
#define REGISTER_OP(op, x) OpHandlers[FEXCore::IR::IROps::OP_##op] = &X86JITCore::Op_##x
  REGISTER_OP(LOADCONTEXT,         LoadContext);
  REGISTER_OP(STORECONTEXT,        StoreContext);
  REGISTER_OP(LOADREGISTER,        Unhandled); // SRA specific, not supported on this backend
  REGISTER_OP(STOREREGISTER,       Unhandled);
  REGISTER_OP(LOADCONTEXTINDEXED,  LoadContextIndexed);
  REGISTER_OP(STORECONTEXTINDEXED, StoreContextIndexed);
  REGISTER_OP(SPILLREGISTER,       SpillRegister);
  REGISTER_OP(FILLREGISTER,        FillRegister);
  REGISTER_OP(LOADFLAG,            LoadFlag);
  REGISTER_OP(STOREFLAG,           StoreFlag);
  REGISTER_OP(LOADMEM,             LoadMem);
  REGISTER_OP(STOREMEM,            StoreMem);
  REGISTER_OP(LOADMEMTSO,          LoadMem);
  REGISTER_OP(STOREMEMTSO,         StoreMem);
  REGISTER_OP(VLOADMEMELEMENT,     VLoadMemElement);
  REGISTER_OP(VSTOREMEMELEMENT,    VStoreMemElement);
  REGISTER_OP(CACHELINECLEAR,      CacheLineClear);
  REGISTER_OP(CACHELINEZERO,       CacheLineZero);
#undef REGISTER_OP
}
}

