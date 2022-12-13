%ifdef CONFIG
{
  "HostFeatures": ["AVX"],
  "RegData": {
    "XMM0": ["0x6162636465666768", "0x7172737475767778", "0xFFFFFFFFFFFFFFFF", "0x7172737475767778"],
    "XMM1": ["0x4142434445464748", "0x5152535455565758", "0xFFFFFFFFFFFFFFFF", "0x5152535455565758"],
    "XMM2": ["0x2020202020202020", "0x2020202020202020", "0x0000000000000000", "0x0000000000000000"],
    "XMM3": ["0x2020202020202020", "0x2020202020202020", "0x0000000000000000", "0x2020202020202020"],
    "XMM4": ["0x2020202020202020", "0x2020202020202020", "0x0000000000000000", "0x0000000000000000"],
    "XMM5": ["0x2020202020202020", "0x2020202020202020", "0x0000000000000000", "0x2020202020202020"]
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif

lea rdx, [rel .data]

vmovapd ymm0, [rdx]
vmovapd ymm1, [rdx + 32]

; Memory operand
vpsubq xmm2, xmm0, [rdx + 32]
vpsubq ymm3, ymm0, [rdx + 32]

; Register only
vpsubq xmm4, xmm0, xmm1
vpsubq ymm5, ymm0, ymm1

hlt

align 32
.data:
dq 0x6162636465666768
dq 0x7172737475767778
dq 0xFFFFFFFFFFFFFFFF
dq 0x7172737475767778

dq 0x4142434445464748
dq 0x5152535455565758
dq 0xFFFFFFFFFFFFFFFF
dq 0x5152535455565758
