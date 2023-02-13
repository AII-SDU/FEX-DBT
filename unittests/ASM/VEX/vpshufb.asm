%ifdef CONFIG
{
  "HostFeatures": ["AVX"],
  "RegData": {
    "XMM5":  ["0x4848484848484848", "0x4848484848484848", "0x0000000000000000", "0x0000000000000000"],
    "XMM6":  ["0x0000000000000000", "0x0000000000000000", "0x0000000000000000", "0x0000000000000000"],
    "XMM7":  ["0x0000000000000000", "0x0000000000000000", "0x0000000000000000", "0x0000000000000000"],
    "XMM8":  ["0x4847464544434241", "0x5857565554535251", "0x0000000000000000", "0x0000000000000000"],
    "XMM9":  ["0x4848484848484848", "0x4848484848484848", "0x5858585858585858", "0x5858585858585858"],
    "XMM10": ["0x0000000000000000", "0x0000000000000000", "0x0000000000000000", "0x0000000000000000"],
    "XMM11": ["0x0000000000000000", "0x0000000000000000", "0x0000000000000000", "0x0000000000000000"],
    "XMM12": ["0x4847464544434241", "0x5857565554535251", "0x5847464544434241", "0x4857565554535251"]
  }
}
%endif

lea rdx, [rel .data]

vmovaps ymm0, [rdx]
vmovaps ymm1, [rdx + 32 * 1]
vmovaps ymm2, [rdx + 32 * 2]
vmovaps ymm3, [rdx + 32 * 3]
vmovaps ymm4, [rdx + 32 * 4]

vpshufb xmm5, xmm0, xmm1
vpshufb xmm6, xmm0, xmm2
vpshufb xmm7, xmm0, xmm3
vpshufb xmm8, xmm0, xmm4

vpshufb ymm9,  ymm0, ymm1
vpshufb ymm10, ymm0, ymm2
vpshufb ymm11, ymm0, ymm3
vpshufb ymm12, ymm0, ymm4

hlt

align 32
.data:
dq 0x4142434445464748
dq 0x5152535455565758
dq 0x4142434445464758
dq 0x5152535455565748

dq 0
dq 0
dq 0
dq 0

dq -1
dq -1
dq -1
dq -1

dq 0x8080808080808080
dq 0x8080808080808080
dq 0x8080808080808080
dq 0x8080808080808080

dq 0x0001020304050607
dq 0x08090A0B0C0D0E0F
dq 0x0001020304050607
dq 0x08090A0B0C0D0E0F
