%ifdef CONFIG
{
  "RegData": {
      "RAX": "0x8000000000000000",
      "RBX": "0xFF",
      "RCX": "0xF00000000000000F",
      "RDX": "0x80000000",
      "RSI": "0xFF",
      "RDI": "0xF000000F"
  },
  "HostFeatures": ["BMI2"]
}
%endif

; Trivial test
mov rax, 1
rorx rax, rax, 1

; More than one bit
mov rbx, 0xFF
rorx rcx, rbx, 4

; Test that we mask the rotation amount above the operand size (should leave rcx's value alone).
rorx rcx, rcx, 64

; 32-bit

; Trivial test
mov edx, 1
rorx edx, edx, 1

; More than one bit
mov esi, 0xFF
rorx edi, esi, 4,

; Test that we mask the rotation amount above the operand size (should leave edi's value alone).
rorx edi, edi, 32

hlt
