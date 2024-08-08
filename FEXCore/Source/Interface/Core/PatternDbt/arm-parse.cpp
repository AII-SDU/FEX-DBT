#include <FEXCore/Utils/LogManager.h>

#include <cstdio>
#include <cstring>
#include <assert.h>
#include <cstdlib>

#include "arm-instr.h"
#include "arm-parse.h"

#define RULE_ARM_INSTR_BUF_LEN 1000000
#define MAX_GUEST_LEN 500
static ARMInstruction *rule_arm_instr_buf;
static int rule_arm_instr_buf_index;

// 初始化 ARM 指令缓冲区
void rule_arm_instr_buf_init(void)
{
    rule_arm_instr_buf = new ARMInstruction[RULE_ARM_INSTR_BUF_LEN];
    if (rule_arm_instr_buf == NULL)
        LogMan::Msg::IFmt( "Cannot allocate memory for rule_arm_instr_buf!\n");

    rule_arm_instr_buf_index = 0;
}

// 分配一个新的 ARM 指令结构体
static ARMInstruction *rule_arm_instr_alloc(uint64_t pc)
{
    ARMInstruction *instr = &rule_arm_instr_buf[rule_arm_instr_buf_index++];
    if (rule_arm_instr_buf_index >= RULE_ARM_INSTR_BUF_LEN) {
        LogMan::Msg::EFmt("Error: rule_arm_instr_buf is not enough!");
        return NULL;
    }

    instr->pc = pc;
    instr->next = NULL;
    return instr;
}

// 解析 ARM 指令的操作码
static int parse_rule_arm_opcode(char *line, ARMInstruction *instr)
{
    char opc_str[20] = "\0";
    int i = 0;

    while(line[i] == ' ' || line[i] == '\t') // skip the first spaces
        i++;

    while(line[i] != ' ' && line[i] != '\n')
        strncat(opc_str, &line[i++], 1);

    set_arm_instr_opc_str(instr, opc_str);

    if (instr->opc == ARM_OPC_CSEL || instr->opc == ARM_OPC_CSET) {
        instr->cc = get_arm_cc(line);
    }

    if (line[i] == ' ')
        return i+1;
    else
        return i;
}

// 解析操作数的比例因子
static int parse_scale(char *line, int idx, ARMOperandScale *pscale)
{
    char direct_str[10] = "\0";
    char scale_str[10] = "\0";
    int iix, i;

    if (line[idx] != ',')
        return idx;

    iix = idx + 2; // skip , and space
    for (i = 0; i < 3; i++) {
        if (line[iix] == '\n')
            break;
        strncat(direct_str, &line[iix++], 1);
    }

    /* Try to set the scale direct based on the string, may fail-- */
    if (set_arm_instr_opd_scale_str(pscale, direct_str))
        return idx;

    /* This is a scale, parse the following immediate or register */
    idx = iix + 1; // skip the space
    if (line[idx] == '#') {
        /* scale value is an immediate */
        idx++; // skip #
        while(line[idx] != ',' && line[idx] != ']' && line[idx] != '\n')
            strncat(scale_str, &line[idx++], 1);
        set_arm_instr_opd_scale_imm_str(pscale, scale_str);
    } else
        LogMan::Msg::EFmt( "Error to parsing operand scale value.");

    return idx;
}

// 解析 ARM 指令的操作数
// 这个函数处理三种主要的操作数类型:立即数、寄存器和内存操作数
// 函数会根据操作数的类型设置相应的字段,并返回解析后的新索引位置
static int parse_rule_arm_operand(char *line, int idx, ARMInstruction *instr, int opd_idx, int index)
{
    ARMOperand *opd = &instr->opd[opd_idx];
    char fc = line[idx];
    // 函数首先检查操作数的第一个字符来确定其类型
    // '#' 表示立即数
    // 'r', 'v', 'q', '{', 'w', 'x' 表示寄存器
    // '[' 表示内存操作数

    // 对于立即数,函数解析其值或符号
    // 对于寄存器,函数解析寄存器名称和可能的比例因子
    // 对于内存操作数,函数解析基址寄存器、索引寄存器、偏移量,以及前索引或后索引模式
    if (fc == '#') {
        /* Immediate Operand
           1. Read immediate value, #XXX*/
        set_arm_opd_type(opd, ARM_OPD_TYPE_IMM);
        idx++; // skip '#'
        fc = line[idx];
        char imm_str[20] = "\0";

        while (line[idx] != ',' && line[idx] != '\n')
            strncat(imm_str, &line[idx++], 1);

        if (fc == 'i' || fc == 'L')
            set_arm_opd_imm_sym_str(opd, imm_str);
        else
            set_arm_opd_imm_val_str(opd, imm_str);
    } else if (fc == 'r' || fc == 'v' || fc == 'q' || fc == '{' || fc == 'w' || fc == 'x') {
        /* Register Operand
           1. Read register string, e.g., "reg0", "reg1".
           2. Check the scale type and content */
        char reg_str[20] = "\0";

        if (fc == '{')
          idx++;

        while (line[idx] != ',' && line[idx] != '\n')
            strncat(reg_str, &line[idx++], 1);

        set_arm_instr_opd_type(instr, opd_idx, ARM_OPD_TYPE_REG);
        set_arm_instr_opd_reg_str(instr, opd_idx, reg_str);

        idx = parse_scale(line, idx, &(instr->opd[opd_idx].content.reg.scale));
    } else if (fc == '[') {
        /* Memory Operand
           1. Read base register string, e.g., "reg0", "reg1".
           2. Read immediate value or index register string.
           3. Read Suffix, e.g., '!' for pre-indexing.*/
        char reg_str[20] = "\0";

        idx++; // skip '['
        while (line[idx] != ',' && line[idx] != ']' && line[idx] != '\n')
            strncat(reg_str, &line[idx++], 1);

        set_arm_instr_opd_type(instr, opd_idx, ARM_OPD_TYPE_MEM);
        set_arm_instr_opd_mem_base_str(instr, opd_idx, reg_str);

        // post-index
        if ((line[idx] == ']') && (line[idx+1] == ',')){
            set_arm_instr_opd_mem_index_type(instr, opd_idx, ARM_MEM_INDEX_TYPE_POST);
            idx++;
        }

        if (line[idx] == ',') {
            idx += 2;

            if (line[idx] == '#') { /* This is an immediate offset (#imm_xxx symbolic chars) */
                char off_str[10] = "\0";
                char tfc;

                idx++;
                tfc = line[idx];

                while (line[idx] != ',' && line[idx] != ']' && line[idx] != '\n')
                  strncat(off_str, &line[idx++], 1);

                if (tfc == 'i')
                  set_arm_opd_mem_off_str(opd, off_str);
                else
                  set_arm_opd_mem_off_val(opd, off_str);
            } else if (line[idx] == 'r') { /* This is an index register */
                char index_reg_str[20] = "\0";
                while (line[idx] != ',' && line[idx] != ']' && line[idx] != '\n')
                    strncat(index_reg_str, &line[idx++], 1);

                set_arm_instr_opd_mem_index_str(instr, opd_idx, index_reg_str);

                idx = parse_scale(line, idx, &(instr->opd[opd_idx].content.mem.scale));
            } else
                LogMan::Msg::IFmt( "Error in parsing memory operand.\n");
        }
        while (line[idx] != ']' && line[idx] != '\n')
            idx++;

        //pre-index
        if ((line[idx] == ']') && (line[idx+1] == '!')){
            set_arm_instr_opd_mem_index_type(instr, opd_idx, ARM_MEM_INDEX_TYPE_PRE);
            idx += 2;
        }
    } else
        LogMan::Msg::EFmt("Error in NO.{} parsing {} operand: unknown operand type: {}.", index, get_arm_instr_opc(instr->opc), line[idx]);

    if (line[idx] == ',')
        return idx+2;
    else if (line[idx] == ']')
        return idx+1;
    else
        return idx;
}

// 调整特定的 ARM 指令(如 ASR, LSL, LSR)为等效的 MOV 指令
static void adjust_arm_instr(ARMInstruction *instr)
{
    if (instr->opc != ARM_OPC_ASR && instr->opc != ARM_OPC_LSL &&
        instr->opc != ARM_OPC_LSR)
        return;

    if (instr->opd[2].type == ARM_OPD_TYPE_IMM) { /* immediate shift */
        instr->opd[1].content.reg.scale.type = ARM_OPD_SCALE_TYPE_SHIFT;
        instr->opd[1].content.reg.scale.imm = instr->opd[2].content.imm;
        switch (instr->opc) {
            case ARM_OPC_ASR:
                instr->opc = ARM_OPC_MOV;
                instr->opd[1].content.reg.scale.content.direct = ARM_OPD_DIRECT_ASR;
                break;
            case ARM_OPC_LSL:
                instr->opc = ARM_OPC_MOV;
                instr->opd[1].content.reg.scale.content.direct = ARM_OPD_DIRECT_LSL;
                break;
            case ARM_OPC_LSR:
                instr->opc = ARM_OPC_MOV;
                instr->opd[1].content.reg.scale.content.direct = ARM_OPD_DIRECT_LSR;
                break;
            default:
                fprintf(stderr, "[ARM] error: unsupported opcode: %d.\n", instr->opc);
                //exit(0);
        }
    } else {
        LogMan::Msg::IFmt( "[ARM] error: unsupported shift type.\n");
        //exit(0);
    }
    set_arm_instr_opd_num(instr, 2);
}

// 解析单条 ARM 指令
static ARMInstruction *parse_rule_arm_instruction(char *line, uint64_t pc, int index)
{
    ARMInstruction *instr = rule_arm_instr_alloc(pc);
    int opd_idx;
    int i;

    i = parse_rule_arm_opcode(line, instr);

    size_t len = strlen(line);

    opd_idx = 0;
    while (i < len && line[i] != '\n')
        i = parse_rule_arm_operand(line, i, instr, opd_idx++, index);

    set_arm_instr_opd_size(instr);
    set_arm_instr_opd_num(instr, opd_idx);

    /* adjust lsl, asr, and etc instructions to mov instructions with two operands */

    return instr;
}

// 解析规则中的 ARM 代码序列
bool parse_rule_arm_code(FILE *fp, TranslationRule *rule)
{
    uint64_t pc = 0;
    ARMInstruction *code_head = NULL;
    ARMInstruction *code_tail = NULL;
    char line[MAX_GUEST_LEN];
    bool ret = true;

    /* parse arm instructions in this rule */
    while(fgets(line, MAX_GUEST_LEN, fp)) {
        if (strstr(line, ".Guest:\n")) {
            fseek(fp, (0-strlen(line)), SEEK_CUR);
            break;
        }

        /* check if this line is a comment */
        char fs = line[0];
        if (fs == '#')
            continue;
        ARMInstruction *cur = parse_rule_arm_instruction(line, pc, rule->index);
        if (!code_head) {
            code_head = code_tail = cur;
        } else {
            code_tail->next = cur;
            code_tail = cur;
        }
        pc += 4; // fake value
    }

    // LogMan::Msg::IFmt( "**** Host {} ****", rule->index);
    // print_arm_instr_seq(code_head);

    rule->arm_host = code_head;

    return ret;
}
