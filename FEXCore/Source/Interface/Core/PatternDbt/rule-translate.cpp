/**
 * @file rule-translate.cpp
 * @brief 实现规则匹配和翻译的功能
 *
 * 本文件包含了用于匹配指令序列与预定义规则，以及执行相应翻译的函数。
 * 主要功能包括初始化缓冲区、匹配操作数、检查翻译规则、执行规则翻译等。
 */

#include "Interface/Core/JIT/Arm64/JITClass.h"

#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/LogManager.h>

#include <cstdio>
#include <assert.h>
#include <cstring>

#include "rule-translate.h"

// 定义各种缓冲区的最大长度
#define MAX_RULE_RECORD_BUF_LEN 800
#define MAX_GUEST_INSTR_LEN 800
#define MAX_HOST_RULE_LEN 800
#define MAX_PARA_OPC 20
#define MAX_MAP_BUF_LEN 1000
#define MAX_HOST_RULE_INSTR_LEN 1000

// 调试标志
static int debug = 0;
// 匹配指令计数器
static int match_insts = 0;
// 匹配计数器
static int match_counter = 10;

/**
 * @brief 重置各种缓冲区和索引
 */
inline void FEXCore::CPU::Arm64JITCore::reset_buffer(void)
{
    imm_map_buf_index = 0;
    label_map_buf_index = 0;
    g_reg_map_buf_index = 0;

    rule_record_buf_index = 0;
    pc_matched_buf_index = 0;

    pc_para_matched_buf_index = 0;
}

/**
 * @brief 保存当前的映射缓冲区索引
 */
inline void FEXCore::CPU::Arm64JITCore::save_map_buf_index(void)
{
    imm_map_buf_index_pre = imm_map_buf_index;
    g_reg_map_buf_index_pre = g_reg_map_buf_index;
    label_map_buf_index_pre = label_map_buf_index;
}

/**
 * @brief 恢复之前保存的映射缓冲区索引
 */
inline void FEXCore::CPU::Arm64JITCore::recover_map_buf_index(void)
{
    imm_map_buf_index = imm_map_buf_index_pre;
    g_reg_map_buf_index = g_reg_map_buf_index_pre;
    label_map_buf_index = label_map_buf_index_pre;
}

/**
 * @brief 初始化映射指针
 */
inline void FEXCore::CPU::Arm64JITCore::init_map_ptr(void)
{
    imm_map = NULL;
    g_reg_map = NULL;
    l_map = NULL;
    reg_map_num = 0;
}

/**
 * @brief 添加规则记录
 * 
 * @param rule 翻译规则
 * @param pc 程序计数器
 * @param t_pc 目标程序计数器
 * @param last_guest 最后一条客户端指令
 * @param update_cc 是否更新条件码
 * @param save_cc 是否保存条件码
 * @param pa_opc 参数化操作码数组
 */
inline void FEXCore::CPU::Arm64JITCore::add_rule_record(TranslationRule *rule, uint64_t pc, uint64_t t_pc,
                                   X86Instruction *last_guest, bool update_cc, bool save_cc, int pa_opc[MAX_PARA_OPC])
{
   

    //assert(rule_record_buf_index < MAX_RULE_RECORD_BUF_LEN);
    if (rule_record_buf_index >= MAX_RULE_RECORD_BUF_LEN) {
        LogMan::Msg::EFmt("Rule record buffer overflow");
        return;
    }
    RuleRecord *p = &rule_record_buf[rule_record_buf_index++];
    p->pc = pc;
    p->target_pc = t_pc;
    p->last_guest = last_guest;
    p->rule = rule;
    p->update_cc = update_cc;
    p->save_cc = save_cc;
    p->imm_map = imm_map;
    p->g_reg_map = g_reg_map;
    p->l_map = l_map;
    for (int i = 0; i < MAX_PARA_OPC; i++)
        p->para_opc[i] = pa_opc[i];
}

/**
 * @brief 添加匹配的PC
 * 
 * @param pc 程序计数器
 */
inline void FEXCore::CPU::Arm64JITCore::add_matched_pc(uint64_t pc)
{   
    if (pc_matched_buf_index >= MAX_GUEST_INSTR_LEN) {
        LogMan::Msg::EFmt("Matched PC buffer overflow");
        return;
    }
    pc_matched_buf[pc_matched_buf_index++] = pc;
}

/**
 * @brief 添加参数化匹配的PC
 * 
 * @param pc 程序计数器
 */
inline void FEXCore::CPU::Arm64JITCore::add_matched_para_pc(uint64_t pc)
{   
    if (pc_para_matched_buf_index >= MAX_GUEST_INSTR_LEN) {
        LogMan::Msg::EFmt("Matched para PC buffer overflow");
        return;
    }
    pc_para_matched_buf[pc_para_matched_buf_index++] = pc;
}

/**
 * @brief 匹配标签
 * 
 * @param lab_str 标签字符串
 * @param t 目标地址
 * @param f fallthrough地址
 * @return bool 是否匹配成功
 */
bool FEXCore::CPU::Arm64JITCore::match_label(char *lab_str, uint64_t t, uint64_t f)
{
    LabelMapping *lmap = l_map;

    while(lmap) {
        if (strcmp(lmap->lab_str, lab_str)) {
            lmap = lmap->next;
            continue;
        }

        return (lmap->target == t && lmap->fallthrough == f);
    }

    // 将此映射添加到标签映射缓冲区
    if (label_map_buf_index >= MAX_MAP_BUF_LEN) {
        LogMan::Msg::EFmt("Label map buffer overflow");
        return false;
    }
    lmap = &label_map_buf[label_map_buf_index++];
    strcpy(lmap->lab_str, lab_str);
    lmap->target = t;
    lmap->fallthrough = f;

    lmap->next = l_map;
    l_map = lmap;

    return true;
}

/**
 * @brief 匹配寄存器
 * 
 * @param greg 客户端寄存器
 * @param rreg 规则寄存器
 * @param regsize 寄存器大小
 * @param HighBits 是否为高位
 * @return bool 是否匹配成功
 */
bool FEXCore::CPU::Arm64JITCore::match_register(X86Register greg, X86Register rreg, uint32_t regsize, bool HighBits)
{
    GuestRegisterMapping *gmap = g_reg_map;

    if (greg == X86_REG_INVALID && rreg == X86_REG_INVALID)
        return true;

    if (greg == X86_REG_INVALID || rreg == X86_REG_INVALID) {
        if(debug)
            LogMan::Msg::IFmt("Unmatch reg: one invalid reg!");
        return false;
    }

    // 使用物理寄存器
    if ((X86_REG_RAX <= rreg && rreg <= X86_REG_XMM15) && greg == rreg)
        return true;

    if (!(X86_REG_REG0 <= rreg && rreg <= X86_REG_REG31)) {
        if(debug)
            LogMan::Msg::IFmt("Unmatch reg: not reg sym!");
        return false;
    }

    // 检查是否已经有这个映射
    while (gmap) {
        if (gmap->sym != rreg) {
            gmap = gmap->next;
            continue;
        }
        if (debug && (gmap->num != greg))
            fprintf(stderr, "Unmatch reg: map conflict: %d %d\n", gmap->num, greg);
        return (gmap->num == greg);
    }
    if (g_reg_map_buf_index >= MAX_MAP_BUF_LEN) {
        LogMan::Msg::EFmt("Register map buffer overflow");
        return false;
    }
    // 将此映射添加到寄存器映射缓冲区
    gmap = &g_reg_map_buf[g_reg_map_buf_index++];
    gmap->sym = rreg;
    gmap->num = greg;

    if (regsize)
      gmap->regsize = regsize;
    else
      gmap->regsize = 0;

    if (HighBits)
      gmap->HighBits = true;
    else
      gmap->HighBits = false;
    ++reg_map_num;

    gmap->next = g_reg_map;
    g_reg_map = gmap;

    return true;
}

/**
 * @brief 匹配立即数
 * 
 * @param val 立即数值
 * @param sym 立即数符号
 * @return bool 是否匹配成功
 */
bool FEXCore::CPU::Arm64JITCore::match_imm(uint64_t val, char *sym)
{
    ImmMapping *imap = imm_map;

    while(imap) {
        if (!strcmp(sym, imap->imm_str)) {
            if (debug && (val != imap->imm_val))
                LogMan::Msg::IFmt( "Unmatch imm: symbol map conflict {} {}", imap->imm_val, val);
            return (val == imap->imm_val);
        }

        imap = imap->next;
    }

    // 将此映射添加到立即数映射缓冲区
    if (imm_map_buf_index >= MAX_MAP_BUF_LEN) {
        LogMan::Msg::EFmt("Immediate map buffer overflow");
        return false;
    }
    imap = &imm_map_buf[imm_map_buf_index++];
    strcpy(imap->imm_str, sym);
    imap->imm_val = val;

    imap->next = imm_map;
    imm_map = imap;

    return true;
}

/**
 * @brief 匹配比例因子
 * 
 * @param gscale 客户端比例因子
 * @param rscale 规则比例因子
 * @return bool 是否匹配成功
 */
bool FEXCore::CPU::Arm64JITCore::match_scale(X86Imm *gscale, X86Imm *rscale)
{
    if (gscale->type == X86_IMM_TYPE_NONE &&
        rscale->type == X86_IMM_TYPE_NONE)
        return true;

    if (rscale->type == X86_IMM_TYPE_VAL){
        if (debug && (gscale->content.val != rscale->content.val))
            LogMan::Msg::IFmt("Unmatch scale value: {} {}", gscale->content.val, rscale->content.val);
        return gscale->content.val == rscale->content.val;
    }
    else if (rscale->type == X86_IMM_TYPE_NONE)
        return match_imm(0, rscale->content.sym);
    else
        return match_imm(gscale->content.val, rscale->content.sym);
}

/**
 * @brief 匹配偏移量
 * 
 * @param goffset 客户端偏移量
 * @param roffset 规则偏移量
 * @return bool 是否匹配成功
 */
bool FEXCore::CPU::Arm64JITCore::match_offset(X86Imm *goffset, X86Imm *roffset)
{
    char *sym;
    int32_t off_val;

    if (roffset->type != X86_IMM_TYPE_NONE &&
        goffset->type == X86_IMM_TYPE_NONE)
        return match_imm(0, roffset->content.sym);

    if (goffset->type == X86_IMM_TYPE_NONE &&
        roffset->type == X86_IMM_TYPE_NONE)
        return true;

    if (roffset->type == X86_IMM_TYPE_NONE &&
        goffset->type == X86_IMM_TYPE_VAL && goffset->content.val == 0)
        return true;

    if (goffset->type == X86_IMM_TYPE_NONE ||
        roffset->type == X86_IMM_TYPE_NONE) {
        if (debug) {
            LogMan::Msg::IFmt("Unmatch offset: none");
        }
        return false;
    }

    sym = roffset->content.sym;
    off_val = goffset->content.val;

    return match_imm(off_val, sym);
}

/**
 * @brief 匹配立即数操作数
 * 
 * @param gopd 客户端立即数操作数
 * @param ropd 规则立即数操作数
 * @return bool 是否匹配成功
 */
bool FEXCore::CPU::Arm64JITCore::match_opd_imm(X86ImmOperand *gopd, X86ImmOperand *ropd)
{
    if (gopd->type == X86_IMM_TYPE_NONE && ropd->type == X86_IMM_TYPE_NONE)
        return true;

    if (ropd->type == X86_IMM_TYPE_VAL)
        return (gopd->content.val == ropd->content.val);
    else if (ropd->type == X86_IMM_TYPE_SYM)
        return match_imm(gopd->content.val, ropd->content.sym);
    else {
        if (debug)
            LogMan::Msg::IFmt("Unmatch imm: type error");
        return false;
    }
}

/**
 * @brief 匹配寄存器操作数
 * 
 * @param gopd 客户端寄存器操作数
 * @param ropd 规则寄存器操作数
 * @param regsize 寄存器大小
 * @return bool 是否匹配成功
 */
bool FEXCore::CPU::Arm64JITCore::match_opd_reg(X86RegOperand *gopd, X86RegOperand *ropd, uint32_t regsize)
{
    // 物理寄存器，但高位不匹配
    if ((X86_REG_RAX <= ropd->num && ropd->num <= X86_REG_XMM15) && gopd->HighBits != ropd->HighBits) {
        if (debug)
            LogMan::Msg::IFmt("Unmatch reg: phy reg, but high bit error.");
        return false;
    }
    return match_register(gopd->num, ropd->num, regsize, gopd->HighBits);
}

/**
 * @brief 匹配内存操作数
 * 
 * @param gopd 客户端内存操作数
 * @param ropd 规则内存操作数
 * @return bool 是否匹配成功
 */
bool FEXCore::CPU::Arm64JITCore::match_opd_mem(X86MemOperand *gopd, X86MemOperand *ropd)
{
    return (match_register(gopd->base, ropd->base) &&
            match_register(gopd->index, ropd->index) &&
            match_offset(&gopd->offset, &ropd->offset) &&
            match_scale(&gopd->scale, &ropd->scale));
}

/**
 * @brief 检查操作数大小
 * 
 * @param ropd 规则操作数
 * @param gsize 客户端大小
 * @param rsize 规则大小
 * @return bool 是否匹配成功
 */
bool FEXCore::CPU::Arm64JITCore::check_opd_size(X86Operand *ropd, uint32_t gsize, uint32_t rsize)
{
    if ((ropd->type == X86_OPD_TYPE_REG && X86_REG_RAX <= ropd->content.reg.num && ropd->content.reg.num <= X86_REG_XMM15)
      || (ropd->type == X86_OPD_TYPE_IMM && ropd->content.imm.isRipLiteral) || ropd->type == X86_OPD_TYPE_MEM) {
            return gsize == rsize;
    }
    return true;
}

/**
 * @brief 匹配操作数
 * 
 * 尝试匹配客户端指令(gopd)和规则(ropd)中的操作数
 * 
 * @param ginstr 客户端指令
 * @param rinstr 规则指令
 * @param opd_idx 操作数索引
 * @return bool 是否匹配成功
 */
bool FEXCore::CPU::Arm64JITCore::match_operand(X86Instruction *ginstr, X86Instruction *rinstr, int opd_idx)
{
    X86Operand *gopd = &ginstr->opd[opd_idx];
    X86Operand *ropd = &rinstr->opd[opd_idx];
    uint32_t regsize = opd_idx == 0 ? ginstr->DestSize : ginstr->SrcSize;

    if (gopd->type != ropd->type) {
        #ifdef DEBUG_RULE_LOG
            writeToLogFile(std::to_string(ThreadState->ThreadManager.PID) + "fex-debug.log", "[INFO] Different operand type\n");
        #else
            LogMan::Msg::IFmt("Different operand {} type", opd_idx);
        #endif
        return false;
    }

    if (!opd_idx && rinstr->DestSize && !check_opd_size(ropd, ginstr->DestSize, rinstr->DestSize)) {
        if (debug) {
                LogMan::Msg::IFmt("Different dest size - RULE: {}, GUEST: {}", rinstr->DestSize, ginstr->DestSize);
        }
        return false;
    }

    if (opd_idx && rinstr->SrcSize && !check_opd_size(ropd, ginstr->SrcSize, rinstr->SrcSize)) {
        if (debug)
            LogMan::Msg::IFmt("Different opd src size.");
        return false;
    }

    if (ropd->type == X86_OPD_TYPE_IMM) {
        if (gopd->content.imm.isRipLiteral != ropd->content.imm.isRipLiteral)
            return false;
        if (x86_instr_test_branch(rinstr) || ropd->content.imm.isRipLiteral) {
            if (ropd->content.imm.type != X86_IMM_TYPE_SYM) {
                LogMan::Msg::EFmt("Expected symbolic immediate for branch instruction or RIP-relative literal");
                return false;
            }
            if (!ropd->content.imm.content.sym) {
                LogMan::Msg::EFmt("Null pointer encountered for symbolic immediate");
                return false;
            }
            return match_label(ropd->content.imm.content.sym, gopd->content.imm.content.val, ginstr->pc + ginstr->InstSize);
        } else /* 匹配立即数操作数 */
            return match_opd_imm(&gopd->content.imm, &ropd->content.imm);
    } else if (ropd->type == X86_OPD_TYPE_REG) {
        return match_opd_reg(&gopd->content.reg, &ropd->content.reg, regsize);
    } else if (ropd->type == X86_OPD_TYPE_MEM) {
        return match_opd_mem(&gopd->content.mem, &ropd->content.mem);
    } else
        fprintf(stderr,"Error: unsupported arm operand type: %d\n", ropd->type);

    return true;
}

// 未使用的函数
static bool check_instr(X86Instruction *ginstr){
    return true;
}

/**
 * @brief 内部规则匹配函数
 * 
 * @param instr 客户端指令
 * @param rule 翻译规则
 * @param tb 解码后的基本块
 * @return bool 是否匹配成功
 */
bool FEXCore::CPU::Arm64JITCore::match_rule_internal(X86Instruction *instr, TranslationRule *rule,
                    FEXCore::Frontend::Decoder::DecodedBlocks const *tb)
{   
    if (!instr || !rule || !tb) {
        LogMan::Msg::EFmt("Invalid input parameters in match_rule_internal");
        return false;
    }
    X86Instruction *p_rule_instr = rule->x86_guest;
    X86Instruction *p_guest_instr = instr;
    X86Instruction *last_guest_instr = NULL;
    int i;

    int j = 0;
    // 初始化此规则
    init_map_ptr();

    while(p_rule_instr) {
        if (p_rule_instr->opc == X86_OPC_INVALID || p_guest_instr->opc == X86_OPC_INVALID) {
            return false;
        }

        if (p_rule_instr->opc == X86_OPC_NOP && p_guest_instr->opc == X86_OPC_NOP) {
            goto next_check;
        }

        // 检查操作码和操作数数量
        if ((p_rule_instr->opc != p_guest_instr->opc) ||  // 操作码不相等
            ((p_rule_instr->opd_num != 0) && (p_rule_instr->opd_num != p_guest_instr->opd_num))) {  // 操作数不相等

            if (debug) {
                if (p_rule_instr->opd_num != p_guest_instr->opd_num)
                    LogMan::Msg::IFmt("Different operand number, rule index {}", rule->index);
            }

            return false;
        }

        // 检查参数化指令
        if ((p_rule_instr->opd_num == 0) && !check_instr(p_guest_instr)) {
            if (debug) {
                LogMan::Msg::IFmt("parameterization check error!");
            }
            return false;
        }

        // 匹配每个操作数
        for(i = 0; i < p_rule_instr->opd_num; i++) {
            if (!match_operand(p_guest_instr, p_rule_instr, i)) {
                if (debug) {
                    #ifdef DEBUG_RULE_LOG
                        writeToLogFile(std::to_string(ThreadState->ThreadManager.PID) + "fex-debug.log", "[INFO] Rule index " + std::to_string(rule->index)
                                                + ", unmatched operand index: " + std::to_string(i) + "\n");
                        output_x86_instr(p_guest_instr, ThreadState->ThreadManager.PID);
                        output_x86_instr(p_rule_instr, ThreadState->ThreadManager.PID);
                    #else
                        LogMan::Msg::IFmt("Rule index {}, unmatched operand index: {}", rule->index, i);
                        print_x86_instr(p_guest_instr);
                        print_x86_instr(p_rule_instr);
                    #endif
                }
                return false;
            }
        }

        next_check:
        last_guest_instr = p_guest_instr;

        // 检查下一条指令
        p_rule_instr = p_rule_instr->next;
        p_guest_instr = p_guest_instr->next;
        j++;
    }

    if (last_guest_instr) {
        bool *p_reg_liveness = last_guest_instr->reg_liveness;
        if ((p_reg_liveness[X86_REG_CF] && (rule->x86_cc_mapping[X86_CF] == 0)) ||
            (p_reg_liveness[X86_REG_SF] && (rule->x86_cc_mapping[X86_SF] == 0)) ||
            (p_reg_liveness[X86_REG_OF] && (rule->x86_cc_mapping[X86_OF] == 0)) ||
            (p_reg_liveness[X86_REG_ZF] && (rule->x86_cc_mapping[X86_ZF] == 0))) {

                if (debug) {
                    LogMan::Msg::IFmt( "Different liveness cc!");
                }
                return false;
            }
    }

    return true;
}
/**
 * @brief 获取标签映射
 * 
 * @param lab_str 标签字符串
 * @param t 用于存储目标地址的指针
 * @param f 用于存储fallthrough地址的指针
 */
void FEXCore::CPU::Arm64JITCore::get_label_map(char *lab_str, uint64_t *t, uint64_t *f)
{
    LabelMapping *lmap = l_map;

    while(lmap) {
        if (!strcmp(lmap->lab_str, lab_str)) {
            *t = lmap->target;
            *f = lmap->fallthrough;
            return;
        }
        lmap = lmap->next;
    }
    LogMan::Msg::EFmt("Label '{}' not found in get_label_map", lab_str);
    *t = 0;  // 设置一个默认值
    *f = 0;
}

/**
 * @brief 获取立即数映射
 * 
 * @param sym 立即数符号
 * @return uint64_t 映射后的立即数值
 */
uint64_t FEXCore::CPU::Arm64JITCore::get_imm_map(char *sym)
{
    ImmMapping *im = imm_map;
    char t_str[50]; // 替换后的字符串
    char t_buf[50]; // 缓冲字符串

    // 由于主机imm_str中的表达式，我们用相应的客户端值替换主机imm_str中的所有imm_xxx，
    // 并解析它以获得表达式的值
    strcpy(t_str, sym);

    while(im) {
        char *p_str = strstr(t_str, im->imm_str);
        while (p_str) {
            size_t len = (size_t)(p_str - t_str);
            strncpy(t_buf, t_str, len);
            sprintf(t_buf + len, "%lu", im->imm_val);
            strncat(t_buf, t_str + len + strlen(im->imm_str), strlen(t_str) - len - strlen(im->imm_str));
            strcpy(t_str, t_buf);
            p_str = strstr(t_str, im->imm_str);
        }
        im = im->next;
    }
    if (debug)
        LogMan::Msg::IFmt("get imm val: {}", t_str);
    return std::stoull(t_str);
}

/**
 * @brief 获取立即数映射的包装函数
 * 
 * @param imm ARM立即数结构指针
 * @return uint64_t 映射后的立即数值
 */
uint64_t FEXCore::CPU::Arm64JITCore::GetImmMapWrapper(ARMImm *imm)
{
    if (imm->type == ARM_IMM_TYPE_NONE)
        return 0;

    if (imm->type == ARM_IMM_TYPE_VAL)
        return imm->content.val;

    return get_imm_map(imm->content.sym);
}

/**
 * @brief 获取客户寄存器映射
 * 
 * @param reg X86寄存器
 * @return ARMRegister 对应的ARM寄存器
 */
static ARMRegister guest_host_reg_map(X86Register& reg)
{
  switch (reg) {
    case X86_REG_RAX:   return ARM_REG_R4;
    case X86_REG_RCX:   return ARM_REG_R5;
    case X86_REG_RDX:   return ARM_REG_R6;
    case X86_REG_RBX:   return ARM_REG_R7;
    case X86_REG_RSP:   return ARM_REG_R8;
    case X86_REG_RBP:   return ARM_REG_R9;
    case X86_REG_RSI:   return ARM_REG_R10;
    case X86_REG_RDI:   return ARM_REG_R11;
    case X86_REG_R8:    return ARM_REG_R12;
    case X86_REG_R9:    return ARM_REG_R13;
    case X86_REG_R10:   return ARM_REG_R14;
    case X86_REG_R11:   return ARM_REG_R15;
    case X86_REG_R12:   return ARM_REG_R16;
    case X86_REG_R13:   return ARM_REG_R17;
    case X86_REG_R14:   return ARM_REG_R19;
    case X86_REG_R15:   return ARM_REG_R29;
    case X86_REG_XMM0:  return ARM_REG_V16;
    case X86_REG_XMM1:  return ARM_REG_V17;
    case X86_REG_XMM2:  return ARM_REG_V18;
    case X86_REG_XMM3:  return ARM_REG_V19;
    case X86_REG_XMM4:  return ARM_REG_V20;
    case X86_REG_XMM5:  return ARM_REG_V21;
    case X86_REG_XMM6:  return ARM_REG_V22;
    case X86_REG_XMM7:  return ARM_REG_V23;
    case X86_REG_XMM8:  return ARM_REG_V24;
    case X86_REG_XMM9:  return ARM_REG_V25;
    case X86_REG_XMM10: return ARM_REG_V26;
    case X86_REG_XMM11: return ARM_REG_V27;
    case X86_REG_XMM12: return ARM_REG_V28;
    case X86_REG_XMM13: return ARM_REG_V29;
    case X86_REG_XMM14: return ARM_REG_V30;
    case X86_REG_XMM15: return ARM_REG_V31;
    default:
      LOGMAN_MSG_A_FMT("Unsupported guest reg num");
      return ARM_REG_INVALID;
  }
}

/**
 * @brief 获取客户寄存器映射
 * 
 * @param reg ARM寄存器引用
 * @param regsize 寄存器大小引用
 * @return ARMRegister 映射后的ARM寄存器
 */
ARMRegister FEXCore::CPU::Arm64JITCore::GetGuestRegMap(ARMRegister& reg, uint32_t& regsize)
{   
    if (reg == ARM_REG_INVALID) {
        LogMan::Msg::EFmt("Invalid ARM register in GetGuestRegMap");
        return ARM_REG_INVALID;
    }
    return GetGuestRegMap(reg, regsize, false);
}

/**
 * @brief 获取客户寄存器映射（带高位标志）
 * 
 * @param reg ARM寄存器引用
 * @param regsize 寄存器大小引用
 * @param HighBits 高位标志
 * @return ARMRegister 映射后的ARM寄存器
 */
ARMRegister FEXCore::CPU::Arm64JITCore::GetGuestRegMap(ARMRegister& reg, uint32_t& regsize, bool&& HighBits)
{
    if (reg == ARM_REG_INVALID)
        LOGMAN_MSG_A_FMT("ArmReg is Invalid!");

    if (ARM_REG_R0 <= reg && reg <= ARM_REG_ZR) {
        regsize = 0;
        HighBits = false;
        return reg;
    }

    GuestRegisterMapping *gmap = g_reg_map;

    while (gmap) {
        if (!strcmp(get_arm_reg_str(reg), get_x86_reg_str(gmap->sym))) {
            regsize = gmap->regsize;
            HighBits = gmap->HighBits;
            ARMRegister armreg = guest_host_reg_map(gmap->num);
            if (armreg == ARM_REG_INVALID) {
                LogMan::Msg::EFmt("Unsupported reg num - arm: {}, x86: {}", get_arm_reg_str(reg), get_x86_reg_str(gmap->num));
                exit(0);
            }
            return armreg;
        }

        gmap = gmap->next;
    }
    LogMan::Msg::EFmt("No matching guest register found for ARM register: {}", get_arm_reg_str(reg));
    return ARM_REG_INVALID;
}

/**
 * @brief 检查指令是否匹配
 * 
 * @param pc 程序计数器
 * @return bool 是否匹配
 */
bool FEXCore::CPU::Arm64JITCore::instr_is_match(uint64_t pc)
{
    int i;
    for (i = 0; i < pc_matched_buf_index; i++) {
        if (pc_matched_buf[i] == pc)
            return true;
    }
    return false;
}

/**
 * @brief 检查是否存在匹配的指令序列
 * 
 * @param pc 程序计数器
 * @return bool 是否存在匹配
 */
bool FEXCore::CPU::Arm64JITCore::instrs_is_match(uint64_t pc)
{
    int i;
    for (i = 0; i < pc_para_matched_buf_index; i++) {
        if (pc_para_matched_buf[i] == pc)
            return true;
    }
    return instr_is_match(pc);
}

/**
 * @brief 获取翻译规则
 * 
 * @return bool 是否存在匹配的翻译规则
 */
bool FEXCore::CPU::Arm64JITCore::tb_rule_matched(void)
{
    return (pc_matched_buf_index != 0);
}

/**
 * @brief 匹配翻译规则
 * 
 * @param pc 程序计数器
 * @return bool 是否存在匹配的翻译规则
 */
bool FEXCore::CPU::Arm64JITCore::check_translation_rule(uint64_t pc)
{
    int i;
    for (i = 0; i < rule_record_buf_index; i++) {
        if (rule_record_buf[i].pc == pc)
            return true;
    }
    return false;
}

/**
 * @brief 获取翻译规则
 * 
 * @param pc 程序计数器
 * @return RuleRecord* 匹配的规则记录指针，如果没有匹配则返回NULL
 */
RuleRecord* FEXCore::CPU::Arm64JITCore::get_translation_rule(uint64_t pc)
{
    int i;
    for (i = 0; i < rule_record_buf_index; i++) {
        if (rule_record_buf[i].pc == pc) {
            rule_record_buf[i].pc = 0xffffffff; // 翻译后禁用它
            return &rule_record_buf[i];
        }
    }
    return NULL;
}

#ifdef PROFILE_RULE_TRANSLATION
uint64_t rule_guest_pc = 0;
uint32_t num_rules_hit = 0;
uint32_t num_rules_replace = 0;
#endif

/**
 * @brief 检查是否需要保存条件码
 * 
 * @param pins 指令序列的起始指针
 * @param icount 指令数量
 * @return bool 是否需要保存条件码
 */
static bool is_save_cc(X86Instruction *pins, int icount)
{
    X86Instruction *head = pins;
    int i;

    for (i = 0; i < icount; i++) {
        if (head->save_cc)
            return true;
        head = head->next;
    }

    return false;
}

/**
 * @brief 尝试将给定的翻译块(tb)中的指令与已有的翻译规则进行匹配
 * 
 * @param tb 指向翻译块的指针
 * @return bool 是否成功匹配
 */
bool FEXCore::CPU::Arm64JITCore::MatchTranslationRule(const void *tb)
{   
    // 输入合法性检查
    if (!tb) {
        LogMan::Msg::EFmt("Invalid input in MatchTranslationRule");
        return false;
    }
    // 将输入转换为 DecodedBlocks 类型
    auto transblock = static_cast<const FEXCore::Frontend::Decoder::DecodedBlocks*>(tb);
    // 如果匹配计数器小于或等于0,不进行匹配
    if (match_counter <= 0)
        return false;

    // 获取翻译块中的第一条x86指令
    X86Instruction *guest_instr = transblock->guest_instr;
    X86Instruction *cur_head = guest_instr;
    int guest_instr_num = 0;
    int i, j;
    bool ismatch = false;

    // 打印日志,表示开始匹配
    LogMan::Msg::IFmt("=====Guest Instr Match Rule Start, Guest PC: 0x{:x}=====\n", guest_instr->pc);
    // 重置各种缓冲区
    reset_buffer();

    // 从最长的规则开始尝试匹配
    while (cur_head) {
        bool opd_para = false;
        // 计算当前指令序列的长度
        if (guest_instr_num <= 0) {
            X86Instruction *t_head = cur_head;
            guest_instr_num = 0;
            while (t_head){
                ++guest_instr_num;
                t_head = t_head->next;
            }
        }
        // 从最长的指令序列开始尝试匹配
        for (i = guest_instr_num; i > 0; i--) {
            // 计算哈希键
            int hindex = rule_hash_key(cur_head, i);

            if (hindex >= MAX_GUEST_LEN)
                continue;
            // 获取对应长度的规则
            /* check rule with length i (number of guest instructions) */
            TranslationRule *cur_rule = cache_rule_table[hindex];
            // 保存当前的映射缓冲区索引
            save_map_buf_index();
            uint32_t num_rules_match = 0;
            // 遍历所有可能的规则
            while (cur_rule) {
                // 如果规则的指令数不匹配,跳过
                if (cur_rule->guest_instr_num != i)
                    goto next;

                num_rules_match++;
                // 尝试匹配规则
                if (match_rule_internal(cur_head, cur_rule, transblock)) {
                    // 如果匹配成功,记录日志(如果启用了相关选项)
                    #if defined(PROFILE_RULE_TRANSLATION) && defined(DEBUG_RULE_LOG)
                        writeToLogFile(std::to_string(ThreadState->ThreadManager.PID) + "fex-debug.log", "[INFO] #####  Rule index " +
                            std::to_string(cur_rule->index) + ", match num:" +
                            std::to_string(num_rules_match) + "#####\n\n");
                    #endif
                    break;
                }

                next:
                cur_rule = cur_rule->next;
                recover_map_buf_index();
            }
            // 如果找到匹配的规则
            if (cur_rule) {
                X86Instruction *temp = cur_head;
                uint64_t target_pc = 0;

                match_insts += i;
                // 计算目标PC
                for (j = 1; j < i; j++)
                    temp = temp->next;
                if (!temp->next) // 最后一条指令
                    target_pc = temp->pc + temp->InstSize;

                int pa_opc[MAX_PARA_OPC];
                if (!opd_para) {
                    // 添加规则记录
                    add_rule_record(cur_rule , cur_head->pc, target_pc, temp,
                        true, is_save_cc(cur_head, i), pa_opc);
                }
                // 更新匹配状态和指针
                if (opd_para) {
                  for (j = 0; j < i; j++) {
                    add_matched_para_pc(cur_head->pc);
                    cur_head = cur_head->next;
                    guest_instr_num--;
                  }
                } else {
                  for (j = 0; j < i; j++) {
                    add_matched_pc(cur_head->pc);
                    cur_head = cur_head->next;
                    guest_instr_num--;
                  }
                }

                ismatch = true;
                break;
            }

            recover_map_buf_index();

            if(1) goto final;
        }
        // 如果没有找到匹配的规则,继续下一条指令
        if (i == 0) {
            /* print unmatched instructions
               if not continuous, record as a new block */
            cur_head = cur_head->next;
            guest_instr_num--;
        }
    }
    final:
    return ismatch;
}

/**
 * @brief 从翻译块中移除客户端指令
 * 
 * @param tb 指向翻译块的指针
 * @param pc 要移除的指令的程序计数器
 */
void remove_guest_instruction(FEXCore::Frontend::Decoder::DecodedBlocks *tb, uint64_t pc)
{
    X86Instruction *head = tb->guest_instr;

    if (!head)
        return;

    if (head->pc == pc) {
        tb->guest_instr = head->next;
        tb->NumInstructions--;
        return;
    }

    while(head->next) {
        if (head->next->pc == pc) {
            head->next = head->next->next;
            tb->NumInstructions--;
            return;
        }
        head = head->next;
    }
}

static ARMInstruction *arm_host;

/**
 * @brief 执行规则翻译
 * 
 * @param rule_r 指向规则记录的指针
 * @param reg_liveness 寄存器活跃度数组
 */
void FEXCore::CPU::Arm64JITCore::do_rule_translation(RuleRecord *rule_r, uint32_t *reg_liveness)
{   
    // 输入合法性检查
    if (!rule_r) {
        LogMan::Msg::EFmt("Invalid rule record in do_rule_translation");
        return;
    }
    TranslationRule *rule;

    if (!rule_r)
        return;
    // 获取翻译规则和相关映射
    rule = rule_r->rule;
    l_map = rule_r->l_map;
    imm_map = rule_r->imm_map;
    g_reg_map = rule_r->g_reg_map;
    // 如果启用了规则翻译性能分析,记录相关信息
    #ifdef PROFILE_RULE_TRANSLATION
        num_rules_replace++;
        #ifdef DEBUG_RULE_LOG
            writeToLogFile(std::to_string(ThreadState->ThreadManager.PID) + "fex-debug.log", "[INFO] ##### PC: 0x" + intToHex(rule_guest_pc) + ", Rule index " +
                                   std::to_string(rule->index) + ", Total replace num:" +
                                   std::to_string(num_rules_replace) + "#####\n\n");
        #else
            LogMan::Msg::IFmt( "##### PC: 0x{:x}, Rule index {}, Total replace num: {} #####\n",
                rule_guest_pc, rule->index, num_rules_replace);
        #endif
    #endif
    // 获取ARM主机代码
    ARMInstruction *arm_code = rule->arm_host;
    arm_host = arm_code;

    // 组装主机指令
    while(arm_code) {
        assemble_arm_instr(arm_code, rule_r);
        arm_code = arm_code->next;
    }
    // 处理目标PC
    if (rule_r->target_pc != 0) {
        if (debug) {
            LogMan::Msg::IFmt("Current TB target_pc: 0x{:x}\n", rule_r->target_pc);
        }

        X86Instruction* last_x86 = rule_r->last_guest;
        // 根据最后一条x86指令的类型,生成不同的退出代码
        if (!x86_instr_test_branch(last_x86)) {
            assemble_arm_exit(rule_r->target_pc);
        } else if (last_x86->opc == X86_OPC_CALL) {
            assemble_arm_exit(0);
        } else if (last_x86->opc == X86_OPC_RET) {
            this->RipReg = ARM_REG_R20;
            assemble_arm_exit(0);
        } else if (last_x86->opc == X86_OPC_JMP) {
            if (last_x86->opd_num && last_x86->opd[0].type == X86_OPD_TYPE_IMM
                    && last_x86->opd[0].content.imm.isRipLiteral) {
                this->RipReg = ARM_REG_R20;
            }
            assemble_arm_exit(0);
        } else {
            // 处理条件分支
            // False Block
            const auto IsTarget1 = JumpTargets2.try_emplace(this->FalseNewRip).first;
            Bind(&IsTarget1->second);
            assemble_arm_exit(this->FalseNewRip);
            // True Block
            const auto IsTarget2 = JumpTargets2.try_emplace(this->TrueNewRip).first;
            Bind(&IsTarget2->second);
            assemble_arm_exit(this->TrueNewRip);
        }
    }
}

/**
 * @brief 检查是否是最后的访问
 * 
 * @param insn 当前指令
 * @param reg 要检查的寄存器
 * @return bool 是否是最后的访问
 */
bool is_last_access(ARMInstruction *insn, ARMRegister reg)
{
    ARMInstruction *head = arm_host;
    int i;

    while(head && head != insn)
        head = head->next;
    if (!head)
        return true;

    head = head->next;

    while(head) {
        for (i = 0; i < head->opd_num; i++) {
            ARMOperand *opd = &head->opd[i];

            if (opd->type == ARM_OPD_TYPE_REG) {
                if (opd->content.reg.num == reg)
                    return false;
            } else if (opd->type == ARM_OPD_TYPE_MEM) {
                if (opd->content.mem.base == reg)
                    return false;
                if (opd->content.mem.index == reg)
                    return false;
            }
        }
        head = head->next;
    }

    return true;
}