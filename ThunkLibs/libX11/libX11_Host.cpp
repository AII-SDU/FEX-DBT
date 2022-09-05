/*
$info$
tags: thunklibs|X11
desc: Handles callbacks and varargs
$end_info$
*/

#include <cstdlib>
#include <stdio.h>

#include <X11/Xlib.h>
#include <X11/Xlibint.h>
#undef min
#undef max

#include <X11/Xutil.h>
#include <X11/Xresource.h>

#include <X11/Xproto.h>

#include <X11/extensions/XKBstr.h>

#include "common/Host.h"
#include <dlfcn.h>
#include <utility>

#include "thunkgen_host_libX11.inl"

#ifdef _M_ARM_64
// This Variadic asm only works for one signature
// ({uint32_t,uint64_t} a_0, size_t count, uint64_t *list)
//
// Variadic ABI for AArch64 (flat uint64_t):
// Arguments 0-7 is in registers
// 8+ stored on to stack
//
// The X11 functions we are calling need an additional nullptr passed in.
// nullptr will be at the end of the list of generated stack items when called through this.
// We will always generate a variadic frame of `count` objects + 1 for nullptr.
//
// Incoming:
// x0 = XIM
// x1 = count
// x2 = array of 64-bit values
// x3 = Function to call
//
// Outgoing:
// x0: Ptr

__attribute__((naked))
void *libX11_Variadic_u64(uint64_t a_0, size_t count, unsigned long *list, void *Func) {
  asm volatile(R"(
    # Move our function to x8, which will be unused
    mov x8, x3

    # Move our list to x9, which will be unused
    mov x9, x2

    # >6 means use stack callback
    cmp x1, 6
    b.gt .stack%=

    # Setup a jump table
    adr x10, .zero%=
    adr x11, .jump_table%=
    ldrb w11, [x11, x1]
    add x10, x10, x11, lsl 2
    br x10

    .zero%=:
      mov x1, 0
      br x8

    .one%=:
      ldr x1, [x9, 0]
      mov x2, #0
      br x8

    .two%=:
      ldp x1, x2, [x9, 0]
      mov x3, 0
      br x8

    .three%=:
      ldp x1, x2, [x9, 0]
      ldr x3, [x9, 16]
      mov x4, 0
      br x8

    .four%=:
      ldp x1, x2, [x9, 0]
      ldp x3, x4, [x9, 16]
      mov x5, 0
      br x8

    .five%=:
      ldp x1, x2, [x9, 0]
      ldp x3, x4, [x9, 16]
      ldr x5, [x9, 32]
      mov x6, 0
      br x8

    .six%=:
      ldp x1, x2, [x9, 0]
      ldp x3, x4, [x9, 16]
      ldp x5, x6, [x9, 32]
      mov x7, 0
      br x8

    .stack%=:
      # Store LR and x28
      stp x28, x30, [sp, -16]!

      # x8 = <arg ptr>
      # x0 = <arg im>
      # x1 = <count>
      # x9 = <list ptr>

      # Stack objects
      # Count >= 7
      # Subtract 6 count objects
      # Leaves us at least 1 (nullptr)
      sub x1, x1, 6

      # Round up to the nearest pair
      and x10, x1, 1
      add x10, x10, x1

      # Multiply by eight to get the size of stack we need to create
      lsl x10, x10, 3

      # Allocate stack space
      sub sp, sp, x10

      # Store how much data we added to the stack in our callee saved register we stole
      mov x28, x10

      # Subtract one member due to nullptr ender
      sub x10, x1, 1

      # x11 - stack offset
      mov x11, sp

      # x12 - load offset
      add x12, x9, (7 * 8)

      cmp x10, 1
      b.eq .single%=
      b.lt .no_single%=

      .load_pair%=:
      ldp x1, x2, [x12], 16
      stp x1, x2, [x11], 16
      sub x10, x10, 8
      cmp x10, 1
      b.gt .load_pair%=
      b.lt .no_single%=

      # One variable at most
      .single%=:
      ldr x1, [x12]
      stp x1, xzr, [x11]
      b .top_reg_args%=

      .no_single%=:
      # Need to store nullptr
      str xzr, [x11]

      .top_reg_args%=:
      ldp x1, x2, [x9, 0]
      ldp x3, x4, [x9, 16]
      ldp x5, x6, [x9, 32]
      ldr x7, [x9, 48]

      # Stack is setup going in to this
      blr x8

      # Move stack back
      add sp, sp, x28
      ldp x28, x30, [sp], 16
      ret

      .jump_table%=:
      .byte (.zero%=  - .zero%=) >> 2
      .byte (.one%=   - .zero%=) >> 2
      .byte (.two%=   - .zero%=) >> 2
      .byte (.three%= - .zero%=) >> 2
      .byte (.four%=  - .zero%=) >> 2
      .byte (.five%=  - .zero%=) >> 2
      .byte (.six%=   - .zero%=) >> 2
  )"
  ::: "memory"
  );
}

#endif

_XIC *fexfn_impl_libX11_XCreateIC_internal(XIM a_0, size_t count, unsigned long *list) {
  switch(count) {
    case 0: return fexldr_ptr_libX11_XCreateIC(a_0, nullptr); break;
    case 1: return fexldr_ptr_libX11_XCreateIC(a_0, list[0], nullptr); break;
    case 2: return fexldr_ptr_libX11_XCreateIC(a_0, list[0], list[1], nullptr); break;
    case 3: return fexldr_ptr_libX11_XCreateIC(a_0, list[0], list[1], list[2], nullptr); break;
    case 4: return fexldr_ptr_libX11_XCreateIC(a_0, list[0], list[1], list[2], list[3], nullptr); break;
    case 5: return fexldr_ptr_libX11_XCreateIC(a_0, list[0], list[1], list[2], list[3], list[4], nullptr); break;
    case 6: return fexldr_ptr_libX11_XCreateIC(a_0, list[0], list[1], list[2], list[3], list[4], list[5], nullptr); break;
    case 7: return fexldr_ptr_libX11_XCreateIC(a_0, list[0], list[1], list[2], list[3], list[4], list[5], list[6], nullptr); break;
    case 8: return fexldr_ptr_libX11_XCreateIC(a_0, list[0], list[1], list[2], list[3], list[4], list[5], list[6], list[7], nullptr); break;
    default:
#ifdef _M_ARM_64
      return reinterpret_cast<_XIC*>(libX11_Variadic_u64(reinterpret_cast<uint64_t>(a_0), count, list, reinterpret_cast<void*>(fexldr_ptr_libX11_XCreateIC)));
#else
      fprintf(stderr, "XCreateIC_internal FAILURE\n");
      return nullptr;
#endif
  }
}

char* fexfn_impl_libX11_XGetICValues_internal(XIC a_0, size_t count, unsigned long *list) {
  switch(count) {
    case 0: return fexldr_ptr_libX11_XGetICValues(a_0, nullptr); break;
    case 1: return fexldr_ptr_libX11_XGetICValues(a_0, list[0], nullptr); break;
    case 2: return fexldr_ptr_libX11_XGetICValues(a_0, list[0], list[1], nullptr); break;
    case 3: return fexldr_ptr_libX11_XGetICValues(a_0, list[0], list[1], list[2], nullptr); break;
    case 4: return fexldr_ptr_libX11_XGetICValues(a_0, list[0], list[1], list[2], list[3], nullptr); break;
    case 5: return fexldr_ptr_libX11_XGetICValues(a_0, list[0], list[1], list[2], list[3], list[4], nullptr); break;
    case 6: return fexldr_ptr_libX11_XGetICValues(a_0, list[0], list[1], list[2], list[3], list[4], list[5], nullptr); break;
    case 7: return fexldr_ptr_libX11_XGetICValues(a_0, list[0], list[1], list[2], list[3], list[4], list[5], list[6], nullptr); break;
    case 8: return fexldr_ptr_libX11_XGetICValues(a_0, list[0], list[1], list[2], list[3], list[4], list[5], list[6], list[7], nullptr); break;
    default:
#ifdef _M_ARM_64
      return reinterpret_cast<char*>(libX11_Variadic_u64(reinterpret_cast<uint64_t>(a_0), count, list, reinterpret_cast<void*>(fexldr_ptr_libX11_XGetICValues)));
#else
      fprintf(stderr, "XGetICValues_internal FAILURE\n");
      abort();
#endif
  }
}

char* fexfn_impl_libX11_XSetICValues_internal(XIC a_0, size_t count, unsigned long *list) {
  switch(count) {
    case 0: return fexldr_ptr_libX11_XSetICValues(a_0, nullptr); break;
    case 1: return fexldr_ptr_libX11_XSetICValues(a_0, list[0], nullptr); break;
    case 2: return fexldr_ptr_libX11_XSetICValues(a_0, list[0], list[1], nullptr); break;
    case 3: return fexldr_ptr_libX11_XSetICValues(a_0, list[0], list[1], list[2], nullptr); break;
    case 4: return fexldr_ptr_libX11_XSetICValues(a_0, list[0], list[1], list[2], list[3], nullptr); break;
    case 5: return fexldr_ptr_libX11_XSetICValues(a_0, list[0], list[1], list[2], list[3], list[4], nullptr); break;
    case 6: return fexldr_ptr_libX11_XSetICValues(a_0, list[0], list[1], list[2], list[3], list[4], list[5], nullptr); break;
    case 7: return fexldr_ptr_libX11_XSetICValues(a_0, list[0], list[1], list[2], list[3], list[4], list[5], list[6], nullptr); break;
    case 8: return fexldr_ptr_libX11_XSetICValues(a_0, list[0], list[1], list[2], list[3], list[4], list[5], list[6], list[7], nullptr); break;
    default:
#ifdef _M_ARM_64
      return reinterpret_cast<char*>(libX11_Variadic_u64(reinterpret_cast<uint64_t>(a_0), count, list, reinterpret_cast<void*>(fexldr_ptr_libX11_XSetICValues)));
#else
      fprintf(stderr, "XSetICValues_internal FAILURE\n");
      abort();
#endif
  }
}

char* fexfn_impl_libX11_XGetIMValues_internal(XIM a_0, size_t count, void **list) {
  switch(count) {
    case 0: return fexldr_ptr_libX11_XGetIMValues(a_0, nullptr); break;
    case 1: return fexldr_ptr_libX11_XGetIMValues(a_0, list[0], nullptr); break;
    case 2: return fexldr_ptr_libX11_XGetIMValues(a_0, list[0], list[1], nullptr); break;
    case 3: return fexldr_ptr_libX11_XGetIMValues(a_0, list[0], list[1], list[2], nullptr); break;
    case 4: return fexldr_ptr_libX11_XGetIMValues(a_0, list[0], list[1], list[2], list[3], nullptr); break;
    case 5: return fexldr_ptr_libX11_XGetIMValues(a_0, list[0], list[1], list[2], list[3], list[4], nullptr); break;
    case 6: return fexldr_ptr_libX11_XGetIMValues(a_0, list[0], list[1], list[2], list[3], list[4], list[5], nullptr); break;
    case 7: return fexldr_ptr_libX11_XGetIMValues(a_0, list[0], list[1], list[2], list[3], list[4], list[5], list[6], nullptr); break;
    case 8: return fexldr_ptr_libX11_XGetIMValues(a_0, list[0], list[1], list[2], list[3], list[4], list[5], list[6], list[7], nullptr); break;
    default:
#ifdef _M_ARM_64
      return reinterpret_cast<char*>(libX11_Variadic_u64(reinterpret_cast<uint64_t>(a_0), count, reinterpret_cast<unsigned long *>(list), reinterpret_cast<void*>(fexldr_ptr_libX11_XGetIMValues)));
#else
      fprintf(stderr, "XGetIMValues_internal FAILURE\n");
      abort();
#endif
  }
}

char* fexfn_impl_libX11_XSetIMValues_internal(XIM a_0, size_t count, void **list) {
  switch(count) {
    case 0: return fexldr_ptr_libX11_XSetIMValues(a_0, nullptr); break;
    case 1: return fexldr_ptr_libX11_XSetIMValues(a_0, list[0], nullptr); break;
    case 2: return fexldr_ptr_libX11_XSetIMValues(a_0, list[0], list[1], nullptr); break;
    case 3: return fexldr_ptr_libX11_XSetIMValues(a_0, list[0], list[1], list[2], nullptr); break;
    case 4: return fexldr_ptr_libX11_XSetIMValues(a_0, list[0], list[1], list[2], list[3], nullptr); break;
    case 5: return fexldr_ptr_libX11_XSetIMValues(a_0, list[0], list[1], list[2], list[3], list[4], nullptr); break;
    case 6: return fexldr_ptr_libX11_XSetIMValues(a_0, list[0], list[1], list[2], list[3], list[4], list[5], nullptr); break;
    case 7: return fexldr_ptr_libX11_XSetIMValues(a_0, list[0], list[1], list[2], list[3], list[4], list[5], list[6], nullptr); break;
    case 8: return fexldr_ptr_libX11_XSetIMValues(a_0, list[0], list[1], list[2], list[3], list[4], list[5], list[6], list[7], nullptr); break;
    default:
#ifdef _M_ARM_64
      return reinterpret_cast<char*>(libX11_Variadic_u64(reinterpret_cast<uint64_t>(a_0), count, reinterpret_cast<unsigned long *>(list), reinterpret_cast<void*>(fexldr_ptr_libX11_XSetIMValues)));
#else
      fprintf(stderr, "XSetIMValues_internal FAILURE\n");
      abort();
#endif
  }
}

XVaNestedList fexfn_impl_libX11_XVaCreateNestedList_internal(int unused_arg, size_t count, void** list) {
  switch(count) {
    case 0: return fexldr_ptr_libX11_XVaCreateNestedList(unused_arg, nullptr); break;
    case 1: return fexldr_ptr_libX11_XVaCreateNestedList(unused_arg, list[0], nullptr); break;
    case 2: return fexldr_ptr_libX11_XVaCreateNestedList(unused_arg, list[0], list[1], nullptr); break;
    case 3: return fexldr_ptr_libX11_XVaCreateNestedList(unused_arg, list[0], list[1], list[2], nullptr); break;
    case 4: return fexldr_ptr_libX11_XVaCreateNestedList(unused_arg, list[0], list[1], list[2], list[3], nullptr); break;
    case 5: return fexldr_ptr_libX11_XVaCreateNestedList(unused_arg, list[0], list[1], list[2], list[3], list[4], nullptr); break;
    case 6: return fexldr_ptr_libX11_XVaCreateNestedList(unused_arg, list[0], list[1], list[2], list[3], list[4], list[5], nullptr); break;
    case 7: return fexldr_ptr_libX11_XVaCreateNestedList(unused_arg, list[0], list[1], list[2], list[3], list[4], list[5], list[6], nullptr); break;
    case 8: return fexldr_ptr_libX11_XVaCreateNestedList(unused_arg, list[0], list[1], list[2], list[3], list[4], list[5], list[6], list[7], nullptr); break;
    default:
#ifdef _M_ARM_64
      return reinterpret_cast<XVaNestedList>(libX11_Variadic_u64(unused_arg, count, reinterpret_cast<unsigned long *>(list), reinterpret_cast<void*>(fexldr_ptr_libX11_XVaCreateNestedList)));
#else
      fprintf(stderr, "XVaCreateNestedList_internal FAILURE\n");
      abort();
#endif
  }
}

Status fexfn_impl_libX11_XInitThreadsInternal(uintptr_t, uintptr_t);

Status fexfn_impl_libX11__XReply(Display*, xReply*, int, Bool);

static int (*ACTUAL_XInitDisplayLock_fn)(Display*) = nullptr;
static int (*INTERNAL_XInitDisplayLock_fn)(Display*) = nullptr;

static int _XInitDisplayLock(Display* display) {
    auto ret = ACTUAL_XInitDisplayLock_fn(display);
    INTERNAL_XInitDisplayLock_fn(display);
    return ret;
}

Status fexfn_impl_libX11_XInitThreadsInternal(uintptr_t GuestTarget, uintptr_t GuestUnpacker) {
    auto ret = fexldr_ptr_libX11_XInitThreads();
    auto _XInitDisplayLock_fn = (int(**)(Display*))dlsym(fexldr_ptr_libX11_so, "_XInitDisplayLock_fn");
    ACTUAL_XInitDisplayLock_fn = std::exchange(*_XInitDisplayLock_fn, _XInitDisplayLock);
    MakeHostTrampolineForGuestFunctionAt(GuestTarget, GuestUnpacker, &INTERNAL_XInitDisplayLock_fn);
    return ret;
}

Status fexfn_impl_libX11__XReply(Display* display, xReply* reply, int extra, Bool discard) {
    for(auto handler = display->async_handlers; handler; handler = handler->next) {
        FinalizeHostTrampolineForGuestFunction(handler->handler);
    }
    return fexldr_ptr_libX11__XReply(display, reply, extra, discard);
}

EXPORTS(libX11)
