#ifndef RULE_TRANSLATE_H
#define RULE_TRANSLATE_H

#include "Interface/Core/Frontend.h"

#include <FEXCore/IR/IR.h>
#include <FEXCore/IR/IntrusiveIRList.h>
#include <FEXCore/IR/RegisterAllocationData.h>

#include "parse.h"

typedef struct ImmMapping {
    char imm_str[20];
    uint64_t imm_val;
    struct ImmMapping *next;
} ImmMapping;

typedef struct GuestRegisterMapping {
    X86Register sym;    /* symbolic register in a rule */
    X86Register num;    /* real register in guest instruction */
    uint32_t regsize;
    bool HighBits;

    struct GuestRegisterMapping *next;
} GuestRegisterMapping;

typedef struct LabelMapping {
    char lab_str[20];
    uint64_t target;
    uint64_t fallthrough;

    struct LabelMapping *next;
} LabelMapping;

typedef struct {
    uint64_t pc;            /* Simulated guest pc */
    uint64_t target_pc;     /* Branch target pc.
                               Only valid if the last instruction of current tb is not branch
                               and covered by this rule */
    X86Instruction *last_guest;   /* last guest instr */
    TranslationRule *rule;  /* Translation rule for this instruction sequence.
                               Only valid at the first instruction */
    bool update_cc;         /* If guest instructions in this rule update condition codes */
    bool save_cc;           /* If the condition code needs to be saved */
    ImmMapping *imm_map;
    GuestRegisterMapping *g_reg_map;
    LabelMapping *l_map;
    int para_opc[20];
} RuleRecord;


bool is_last_access(ARMInstruction *, ARMRegister);
#endif
