#ifndef RULE_MATCHER_H
#define RULE_MATCHER_H

#include "Interface/Context/Context.h"
#include "Interface/Core/Frontend.h"
#include "Interface/Core/JIT/Arm64/JITClass.h"
#include "Interface/Core/X86Tables/X86Tables.h"

#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/X86Enums.h>

#include <vector>

#include "x86-instr.h"
#include "arm-instr.h"
#include "rule-translate.h"

namespace FEXCore::CPU {
class Arm64JITCore;
}

namespace FEXCore::Rule {

enum ARCH {
    ARM64 = 0,
    RV64 = 1,
};

// 规则匹配主结构
class RuleMatcher {
public:
    // Arch: 指定Host架构
    // GPRMappedIdx： 指定RAX~R15,RIP 映射到Host的寄存器
    // GPRTempIdx: 指定生成Host指令时可以使用的临时通用寄存器
    // XMMMappedIdx: 指定XMM0～XMM15 映射到Host的向量寄存器
    // XMMTempIdx: 指定生成Host指令时可以使用的临时向量寄存器
	RuleMatcher(FEXCore::Context::ContextImpl *Ctx,
				FEXCore::Core::InternalThreadState *Thread);

	// 准备工作，用作进程初始化时进行规则的解析
	static void Prepare();

	// 基本块匹配函数，Block为传入的待匹配的X86指令基本块
	// 返回匹配成功与否
	/* 传入的基本块结构定义如下，X86Instrunction为PatternDBT自定义，其结构需要由头文件导出
	  struct DecodedBlocks final {
            uint64_t Entry{};
            uint32_t Size{};
            uint32_t NumInstructions{};
            uint64_t ImplicitLinkTarget{};
            FEXCore::X86Tables::DecodedInst *DecodedInstructions;
            bool HasInvalidInstruction{};
            X86Instruction *guest_instr;
        };
    */
	[[nodiscard]] bool MatchBlock(const void *tb);

	// 指定EmiCode释放代码的位置
	void SetCodeBuffer(uint8_t* Buffer, size_t Size);

    // 设置规则批生成指令的序言代码，添加到开头
    void SetPrologue(uint8_t* Code, size_t Size);
    // 设置规则批生成指令的尾声代码，添加到结尾ret之前
    void SetEpilogue(uint8_t* Code, size_t Size);

	// 根据规则，生成匹配的基本块对应的Host指令
	// 另外：每个块结束时，将Guest对应的目标地址（跳转或者函数调用）写入RIP对应的Host的寄存器，
	// 不尝试链接其他块，因为外部不会传入其他翻译的块
	// 并以ret指令返回到Dispatcher，作为结束指令
	std::pair<uint8_t*, size_t> EmitCode();

	// 查询基本块匹配时的规则index
	int GetRuleIndex(uint64_t pc);

    // 将 FEXCore 解码的指令转换为自定义 X86Instruction 格式
    void DecodeInstToX86Inst(FEXCore::X86Tables::DecodedInst *DecodeInst, X86Instruction *instr, uint64_t pid);

    friend class FEXCore::CPU::Arm64JITCore;

    static ARCH Arch;
    static std::vector<int> GPRMappedIdx;
    static std::vector<int> GPRTempIdx;
    static std::vector<int> XMMMappedIdx;
    static std::vector<int> XMMTempIdx;

private:
    /* Try to match instructions in this tb to existing rules */
    ImmMapping imm_map_buf[1000];
    int imm_map_buf_index;

    LabelMapping label_map_buf[1000];
    int label_map_buf_index;

    GuestRegisterMapping g_reg_map_buf[1000];
    int g_reg_map_buf_index;
    int reg_map_num;

    RuleRecord rule_record_buf[800];
    int rule_record_buf_index;

    uint64_t pc_matched_buf[800];
    int pc_matched_buf_index;

    int imm_map_buf_index_pre;
    int g_reg_map_buf_index_pre;
    int label_map_buf_index_pre;

    ImmMapping *imm_map;
    GuestRegisterMapping *g_reg_map;
    LabelMapping *l_map;

    uint64_t pc_para_matched_buf[800];
    int pc_para_matched_buf_index;

    inline void reset_buffer(void);
    inline void save_map_buf_index(void);
    inline void recover_map_buf_index(void);
    inline void init_map_ptr(void);

    inline void add_rule_record(TranslationRule *rule, uint64_t pc, uint64_t t_pc,
                              X86Instruction *last_guest, bool update_cc, bool save_cc, int pa_opc[20]);
    inline void add_matched_pc(uint64_t pc);
    inline void add_matched_para_pc(uint64_t pc);
    bool match_label(char *lab_str, uint64_t t, uint64_t f);
    bool match_register(X86Register greg, X86Register rreg, uint32_t regsize = 0, bool HighBits = false);
    bool match_imm(uint64_t val, char *sym);
    bool match_scale(X86Imm *gscale, X86Imm *rscale);
    bool match_offset(X86Imm *goffset, X86Imm *roffset);
    bool match_opd_imm(X86ImmOperand *gopd, X86ImmOperand *ropd);
    bool match_opd_reg(X86RegOperand *gopd, X86RegOperand *ropd, uint32_t regsize = 0);
    bool match_opd_mem(X86MemOperand *gopd, X86MemOperand *ropd);
    bool check_opd_size(X86Operand *ropd, uint32_t gsize, uint32_t rsize);
    bool match_operand(X86Instruction *ginstr, X86Instruction *rinstr, int opd_idx);
    bool match_rule_internal(X86Instruction *instr, TranslationRule *rule,
                            const FEXCore::Frontend::Decoder::DecodedBlocks *tb);

    bool InstIsMatch(uint64_t pc);
    bool instrs_is_match(uint64_t pc);
    bool tb_rule_matched(void);
    bool check_translation_rule(uint64_t pc);
    RuleRecord* GetTranslationRule(uint64_t pc);
    void GenHostCode(FEXCore::CPU::Arm64JITCore *JIT, RuleRecord *rule_r);

    FEXCore::Context::Context *Ctx;
    FEXCore::Core::InternalThreadState *Thread;
    uint8_t* CodeBuffer;
    size_t   CodeBufferSize;
    uint8_t* PrologueCode;
    size_t   PrologueSize;
    uint8_t* EpilogueCode;
    size_t   EpilogueSize;
};
}
#endif
