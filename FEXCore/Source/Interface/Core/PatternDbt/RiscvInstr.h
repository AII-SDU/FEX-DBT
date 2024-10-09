#ifndef RISCV_INSTR_H
#define RISCV_INSTR_H

#include <stdint.h>
#include <stddef.h>

#define RISCV_MAX_OPERAND_NUM 4
#define RISCV_REG_NUM 32 /* x0 - x31 */

/* RISC-V 64-bit registers */
typedef enum {
    RISCV_REG_INVALID = 0,

    /* Physical registers for disassembled instructions */
    RISCV_REG_X0,  RISCV_REG_X1,  RISCV_REG_X2,  RISCV_REG_X3,
    RISCV_REG_X4,  RISCV_REG_X5,  RISCV_REG_X6,  RISCV_REG_X7,
    RISCV_REG_X8,  RISCV_REG_X9,  RISCV_REG_X10, RISCV_REG_X11,
    RISCV_REG_X12, RISCV_REG_X13, RISCV_REG_X14, RISCV_REG_X15,
    RISCV_REG_X16, RISCV_REG_X17, RISCV_REG_X18, RISCV_REG_X19,
    RISCV_REG_X20, RISCV_REG_X21, RISCV_REG_X22, RISCV_REG_X23,
    RISCV_REG_X24, RISCV_REG_X25, RISCV_REG_X26, RISCV_REG_X27,
    RISCV_REG_X28, RISCV_REG_X29, RISCV_REG_X30, RISCV_REG_X31,

    RISCV_REG_END
} RISCVRegister;

typedef enum {
    RISCV_OPC_INVALID = 0,

    RISCV_OPC_LB,
    RISCV_OPC_LH,
    RISCV_OPC_LW,
    RISCV_OPC_LD,
    RISCV_OPC_LI,
    RISCV_OPC_LR,
    RISCV_OPC_SB,
    RISCV_OPC_SH,
    RISCV_OPC_SW,
    RISCV_OPC_SD,

    RISCV_OPC_MOV,
    RISCV_OPC_MV,
    RISCV_OPC_ADD,
    RISCV_OPC_SUB,
    RISCV_OPC_AND,
    RISCV_OPC_OR,
    RISCV_OPC_XOR,
    RISCV_OPC_SLT,
    RISCV_OPC_SLTU,

    RISCV_OPC_BEQ,
    RISCV_OPC_BNE,
    RISCV_OPC_BLT,
    RISCV_OPC_BGE,
    RISCV_OPC_BLTU,
    RISCV_OPC_BGEU,

    RISCV_OPC_JAL,
    RISCV_OPC_JALR,

    RISCV_OPC_END
} RISCVOpcode;

typedef enum {
    RISCV_OPD_TYPE_INVALID = 0,
    RISCV_OPD_TYPE_IMM,
    RISCV_OPD_TYPE_REG,
    RISCV_OPD_TYPE_MEM
} RISCVOperandType;

typedef struct {
    uint32_t val;    /* Immediate value */
} RISCVImm;

typedef struct {
    RISCVRegister num;
    size_t Index;
} RISCVRegOperand;

typedef struct {
    RISCVOperandType type;

    union {
        RISCVImm imm;
        RISCVRegOperand reg;
    } content;
} RISCVOperand;

typedef struct RISCVInstruction {
    uint64_t pc;    /* simulated PC of this instruction */

    RISCVOpcode opc;      /* Opcode of this instruction */
    RISCVOperand opd[RISCV_MAX_OPERAND_NUM];    /* Operands of this instruction */
    size_t opd_num;     /* number of operands of this instruction */
    size_t OpSize;      /* size of operands: 1, 2, 4, 8, or 16 bytes */

    struct RISCVInstruction *prev; /* previous instruction in this block */
    struct RISCVInstruction *next; /* next instruction in this block */

    bool reg_liveness[RISCV_REG_NUM]; /* liveness of each register after this instruction */

    uint32_t raw_binary; /* raw binary code of this instruction */
} RISCVInstruction;

void print_riscv_instr_seq(RISCVInstruction *instr_seq);
void print_riscv_instr(RISCVInstruction *instr_seq);

void set_riscv_instr_opc(RISCVInstruction *instr, RISCVOpcode opc);
void set_riscv_instr_opd_num(RISCVInstruction *instr, size_t num);
void set_riscv_instr_opd_type(RISCVInstruction *instr, int opd_index, RISCVOperandType type);
void set_riscv_instr_opd_imm(RISCVInstruction *instr, int opd_index, uint32_t val);
void set_riscv_instr_opd_reg(RISCVInstruction *instr, int opd_index, int regno);

const char *get_riscv_instr_opc(RISCVOpcode);
const char *get_riscv_reg_str(RISCVRegister);
RISCVRegister get_riscv_reg(int regno);

#endif
