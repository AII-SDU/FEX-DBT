/**
 * @file arm-parse.cpp
 * @brief ARM指令解析器的实现
 *
 * 本文件包含了用于解析ARM指令的各种函数和数据结构。
 * 主要功能包括解析ARM指令的操作码、操作数，以及整个ARM代码序列。
 * 这些功能主要用于解析转换规则中的ARM代码部分。
 */

#include <FEXCore/Utils/LogManager.h>

#include <cstdio>
#include <cstring>
#include <assert.h>
#include <cstdlib>

#include "arm-instr.h"
#include "arm-parse.h"

// ARM指令缓冲区的最大长度
#define RULE_ARM_INSTR_BUF_LEN 1000000
// 单条指令的最大长度
#define MAX_GUEST_LEN 500

// ARM指令缓冲区
static ARMInstruction *rule_arm_instr_buf;
// ARM指令缓冲区当前索引
static int rule_arm_instr_buf_index;

/**
 * @brief 初始化ARM指令缓冲区
 * 
 * 分配内存并初始化ARM指令缓冲区。
 */
void rule_arm_instr_buf_init(void)
{
    rule_arm_instr_buf = new ARMInstruction[RULE_ARM_INSTR_BUF_LEN];
    if (rule_arm_instr_buf == NULL)
        LogMan::Msg::IFmt( "Cannot allocate memory for rule_arm_instr_buf!\n");

    rule_arm_instr_buf_index = 0;
}

/**
 * @brief 分配一个新的ARM指令结构体
 * 
 * @param pc 指令的程序计数器值
 * @return ARMInstruction* 新分配的ARM指令结构体指针
 */
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

/**
 * @brief 解析ARM指令的操作码
 * 
 * @param line 包含指令的字符串
 * @param instr 指向ARMInstruction结构的指针
 * @return int 解析后的字符串索引
 */
static int parse_rule_arm_opcode(char *line, ARMInstruction *instr)
{
    char opc_str[20] = "\0";
    int i = 0;

    while(line[i] == ' ' || line[i] == '\t') // 跳过前导空格
        i++;

    while(line[i] != ' ' && line[i] != '\n')
        strncat(opc_str, &line[i++], 1);

    set_arm_instr_opc_str(instr, opc_str);

    // 处理特殊指令的条件码
    if (instr->opc == ARM_OPC_CSEL || instr->opc == ARM_OPC_CSET) {
        instr->cc = get_arm_cc(line);
    }

    if (line[i] == ' ')
        return i+1;
    else
        return i;
}

/**
 * @brief 解析操作数的比例因子
 * 
 * @param line 包含操作数的字符串
 * @param idx 当前解析的起始索引
 * @param pscale 指向ARMOperandScale结构的指针
 * @return int 解析后的字符串索引
 */
static int parse_scale(char *line, int idx, ARMOperandScale *pscale)
{
    char direct_str[10] = "\0";
    char scale_str[10] = "\0";
    int iix, i;

    if (line[idx] != ',')
        return idx;

    iix = idx + 2; // 跳过逗号和空格
    for (i = 0; i < 3; i++) {
        if (line[iix] == '\n')
            break;
        strncat(direct_str, &line[iix++], 1);
    }

    // 尝试设置比例因子的方向，可能失败
    if (set_arm_instr_opd_scale_str(pscale, direct_str))
        return idx;

    // 这是一个比例因子，解析后面的立即数或寄存器
    idx = iix + 1; // 跳过空格
    if (line[idx] == '#') {
        // 比例值是一个立即数
        idx++; // 跳过 '#'
        while(line[idx] != ',' && line[idx] != ']' && line[idx] != '\n')
            strncat(scale_str, &line[idx++], 1);
        set_arm_instr_opd_scale_imm_str(pscale, scale_str);
    } else
        LogMan::Msg::EFmt( "Error to parsing operand scale value.");

    return idx;
}

/**
 * @brief 解析ARM指令的操作数
 * 
 * 这个函数处理三种主要的操作数类型：立即数、寄存器和内存操作数。
 * 函数会根据操作数的类型设置相应的字段，并返回解析后的新索引位置。
 * 
 * @param line 包含操作数的字符串
 * @param idx 当前解析的起始索引
 * @param instr 指向ARMInstruction结构的指针
 * @param opd_idx 操作数在指令中的索引
 * @param index 指令在序列中的索引（用于错误报告）
 * @return int 解析后的字符串索引
 */
static int parse_rule_arm_operand(char *line, int idx, ARMInstruction *instr, int opd_idx, int index)
{
    ARMOperand *opd = &instr->opd[opd_idx];
    char fc = line[idx];
    // 函数首先检查操作数的第一个字符来确定其类型
    // '#' 表示立即数
    // 'r', 'v', 'q', '{', 'w', 'x' 表示寄存器
    // '[' 表示内存操作数
    
    // 根据首字符判断操作数类型
    if (fc == '#') {
        // 立即数操作数
        set_arm_opd_type(opd, ARM_OPD_TYPE_IMM);
        idx++; // 跳过 '#'
        fc = line[idx];
        char imm_str[20] = "\0";

        while (line[idx] != ',' && line[idx] != '\n')
            strncat(imm_str, &line[idx++], 1);

        if (fc == 'i' || fc == 'L')
            set_arm_opd_imm_sym_str(opd, imm_str);
        else
            set_arm_opd_imm_val_str(opd, imm_str);
    } else if (fc == 'r' || fc == 'v' || fc == 'q' || fc == '{' || fc == 'w' || fc == 'x') {
        // 寄存器操作数
        char reg_str[20] = "\0";

        if (fc == '{')
          idx++;

        while (line[idx] != ',' && line[idx] != '\n')
            strncat(reg_str, &line[idx++], 1);

        set_arm_instr_opd_type(instr, opd_idx, ARM_OPD_TYPE_REG);
        set_arm_instr_opd_reg_str(instr, opd_idx, reg_str);

        idx = parse_scale(line, idx, &(instr->opd[opd_idx].content.reg.scale));
    } else if (fc == '[') {
        // 内存操作数
        char reg_str[20] = "\0";

        idx++; // 跳过 '['
        while (line[idx] != ',' && line[idx] != ']' && line[idx] != '\n')
            strncat(reg_str, &line[idx++], 1);

        set_arm_instr_opd_type(instr, opd_idx, ARM_OPD_TYPE_MEM);
        set_arm_instr_opd_mem_base_str(instr, opd_idx, reg_str);

        // 后索引
        if ((line[idx] == ']') && (line[idx+1] == ',')){
            set_arm_instr_opd_mem_index_type(instr, opd_idx, ARM_MEM_INDEX_TYPE_POST);
            idx++;
        }

        if (line[idx] == ',') {
            idx += 2;

            if (line[idx] == '#') { // 这是一个立即数偏移
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
            } else if (line[idx] == 'r') { // 这是一个索引寄存器
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

        // 前索引
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

/**
 * @brief 调整特定的ARM指令(如 ASR, LSL, LSR)为等效的MOV指令
 * 
 * @param instr 指向ARMInstruction结构的指针
 */
static void adjust_arm_instr(ARMInstruction *instr)
{
    if (instr->opc != ARM_OPC_ASR && instr->opc != ARM_OPC_LSL &&
        instr->opc != ARM_OPC_LSR)
        return;

    if (instr->opd[2].type == ARM_OPD_TYPE_IMM) { // 立即数移位
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

/**
 * @brief 解析单条ARM指令
 * 
 * @param line 包含指令的字符串
 * @param pc 指令的程序计数器值
 * @param index 指令在序列中的索引
 * @return ARMInstruction* 解析后的ARM指令结构体指针
 */
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

    // 调整特定指令（如 lsl, asr 等）为带有两个操作数的 mov 指令
    adjust_arm_instr(instr);

    return instr;
}

/**
 * @brief 解析规则中的ARM代码序列
 * 
 * @param fp 指向规则文件的文件指针
 * @param rule 指向TranslationRule结构的指针
 * @return bool 解析是否成功
 */
bool parse_rule_arm_code(FILE *fp, TranslationRule *rule)
{
    uint64_t pc = 0;
    ARMInstruction *code_head = NULL;
    ARMInstruction *code_tail = NULL;
    char line[MAX_GUEST_LEN];
    bool ret = true;

    // 解析规则中的ARM指令
    // 解析规则中的ARM指令
    while(fgets(line, MAX_GUEST_LEN, fp)) {
        if (strstr(line, ".Guest:\n")) {
            fseek(fp, (0-strlen(line)), SEEK_CUR);
            break;
        }

        // 检查这行是否是注释
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
        pc += 4; // 假设的值，实际应根据指令长度调整
    }

    // 以下注释掉的代码可能用于调试
    // LogMan::Msg::IFmt( "**** Host {} ****", rule->index);
    // print_arm_instr_seq(code_head);

    rule->arm_host = code_head;

    return ret;
}