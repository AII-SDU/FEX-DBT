#include <FEXCore/Utils/LogManager.h>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <assert.h>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <filesystem>

#include "arm-parse.h"
#include "x86-parse.h"
#include "parse.h"


static const int cache_index[] = {2483,
896,
2,
7,
121,
252,
2484,
37,
2482,
138,
446,
101,
2485,
176,
111,
46,
79,
23,
876,
189,
44,
88,
5,
212,
437,
339,
51,
1873,
218,
58,
299,
39,
675,
1026,
2349,
59,
753,
2216,
611,
64,
820,
2492,
300,
317,
1659,
794,
1237,
440,
206,
720,
1647,
9,
549,
2079,
1089,
33,
940,
167,
78,
2488,
328,
2490,
22,
170,
186,
1950,
11,
585,
24,
1401,
2295,
12,
191,
1239,
183,
482,
201,
655,
2486,
2375,
2491,
226,
2449,
840,
102,
2487,
844,
1336,
68,
53,
1875,
462,
2204};

static TranslationRule *rule_buf;
static int rule_buf_index;
static size_t current_rule_buf_len = RULE_BUF_LEN;

int cache_counter = 0;

TranslationRule *rule_table[MAX_GUEST_LEN] = {NULL};
TranslationRule *cache_rule_table[MAX_GUEST_LEN] = {NULL};

// 初始化规则缓冲区
static void rule_buf_init(void)
{   
    // 分配内存用于存储翻译规则
    rule_buf = new TranslationRule[current_rule_buf_len];
    if (rule_buf == NULL)
        LogMan::Msg::IFmt( "Cannot allocate memory for rule_buf!\n");

    rule_buf_index = 0;
}

// 分配一个新的翻译规则
static TranslationRule *rule_alloc(void)
{
    TranslationRule *rule = &rule_buf[rule_buf_index++];
    int i;

    // if (rule_buf_index >= RULE_BUF_LEN)
    //     LogMan::Msg::IFmt( "Error: rule_buf is not enough!\n");
    // 检查是否还有足够的空间
    if (rule_buf_index >= current_rule_buf_len) {
        LogMan::Msg::EFmt("Error: rule_buf is not enough! Trying to allocate more memory...");
        
        // 尝试重新分配更大的内存
        TranslationRule *new_buf = new (std::nothrow) TranslationRule[current_rule_buf_len * 2];
        if (new_buf == NULL) {
            LogMan::Msg::EFmt("Failed to allocate more memory. Exiting.");
            exit(1);
        }
        
        // 复制旧数据并更新指针
        std::memcpy(new_buf, rule_buf, sizeof(TranslationRule) * current_rule_buf_len);
        delete[] rule_buf;
        rule_buf = new_buf;
        current_rule_buf_len *= 2;
        }
    
    // 初始化规则的其他字段
    rule->index = 0;
    rule->arm_host = NULL;
    rule->x86_guest = NULL;
    rule->guest_instr_num = 0;
    rule->next = NULL;
    rule->prev = NULL;
    #ifdef PROFILE_RULE_TRANSLATION
    rule->hit_num = 0;
    rule->print_flag = 0;
    #endif
    
    // 初始化条件码映射
    for (i = 0; i < X86_CC_NUM; i++)
        rule->x86_cc_mapping[i] = 1;

    rule->match_counter = 0;

    return rule;
}

// 初始化所有缓冲区
static void init_buf(void)
{
    rule_arm_instr_buf_init();
    rule_x86_instr_buf_init();

    rule_buf_init();
}

// 安装规则到规则表中
static void install_rule(TranslationRule *rule)
{
    int index = rule_hash_key(rule->x86_guest, rule->guest_instr_num);

    //assert(index < MAX_GUEST_LEN);
    if (index < 0 || index >= MAX_GUEST_LEN) {
        LogMan::Msg::EFmt("Invalid index {} for rule installation. Skipping.", index);
        return;
    }
    int i;

    // 检查是否为缓存规则
    for (i = 0; i < 93; i++){
        if (cache_index[i] == rule->index){
            ++cache_counter;
            rule->next = cache_rule_table[index];
            cache_rule_table[index] = rule;
            return;
        }
    }

     // 非缓存规则,添加到普通规则表
    rule->next = rule_table[index];
    if (rule_table[index])
        rule_table[index]->prev = rule;
    rule_table[index] = rule;

}

// 规则索引
int ruleindex = 0;

// 安装规则的替代方法
static void install_rule2(TranslationRule *rule)
{   
    // 安全检查
    //assert(ruleindex < MAX_GUEST_LEN);
    if (ruleindex < 0 || ruleindex >= MAX_GUEST_LEN) {
        LogMan::Msg::EFmt("Invalid index for rule installation. Skipping.");
        return;
    }
    
    // 安装规则的逻辑
    if (ruleindex) {
      rule->prev = rule_table[ruleindex-1];
      rule_table[ruleindex-1]->next = rule;
    }
    rule_table[ruleindex] = rule;
    rule->next = nullptr;
    ruleindex++;
}

// 计算规则的哈希键
int rule_hash_key(X86Instruction *x86_insn, int num)
{
    X86Instruction *p_x86_insn = x86_insn;
    int sum = 0, cnt = 0;

    while(p_x86_insn) {
        sum += p_x86_insn->opc;
        p_x86_insn = p_x86_insn->next;
        cnt++;
    }

    if(cnt < num)
      LogMan::Msg::IFmt( "num: {} < cnt:{}, X86 inst num error!\n", num, cnt);

    return (sum/num);
}

// 获取规则缓冲区的首地址
TranslationRule *get_rule(void)
{
    return &rule_buf[0];
}

// 清空日志文件
static void flush_file(uint64_t pid)
{
    std::filesystem::path homeDir = std::filesystem::path(getenv("HOME"));
    std::filesystem::path combinedPath = homeDir / (std::to_string(pid) + "fex-asm.log");
    std::string inputFile = combinedPath.string();
    std::ofstream file(inputFile, std::ios::trunc);
    if (!file.is_open()) {
      LogMan::Msg::EFmt("Failed to open file!");
      exit(0);
    }
    file.close();

    std::filesystem::path combinedPath2 = homeDir / (std::to_string(pid) + "fex-debug.log");
    std::string inputFile2 = combinedPath2.string();
    std::ofstream file2(inputFile2, std::ios::trunc);
    if (!file2.is_open()) {
      LogMan::Msg::EFmt("Failed to open file!");
      exit(0);
    }
    file2.close();
}

// 解析翻译规则
void ParseTranslationRules(uint64_t pid)
{   LogMan::Msg::IFmt("== Loading pid", pid);
    std::filesystem::path homeDir = std::filesystem::path(getenv("HOME"));
    std::filesystem::path combinedPath = homeDir / "rules4all";
    const char* rule_file = combinedPath.c_str();
    TranslationRule *rule = NULL;
    int counter = 0;
    int install_counter = 0;
    int i;
    char line[MAX_GUEST_LEN];
    char *substr;
    FILE *fp;

    /* 1. init environment */
    init_buf();


    LogMan::Msg::IFmt("== Loading translation rules from {}...\n", rule_file);
    
    /* 2. open the rule file and parse it */
    fp = fopen(rule_file, "r");
    if (fp == NULL) {
        LogMan::Msg::IFmt("== No translation rule file found.\n");
        return;
    }

    while(!feof(fp)) {
        if(fgets(line, MAX_GUEST_LEN, fp) == NULL)
            break;

        /* check if this line is a comment */
        char fs = line[0];
        if (fs == '#' || fs == '\n')
            continue;

        if ((substr = strstr(line, ".Guest:\n")) != NULL) {
            char idx[20] = "\0";

            rule = rule_alloc();
            counter++;

            /* get the index of this rule */
            strncpy(idx, line, strlen(line) - strlen(substr));
            rule->index = atoi(idx);

            parse_rule_x86_code(fp, rule);

        } else if (strstr(line, ".Host:\n")) {
            if (parse_rule_arm_code(fp, rule)) {

                /* install this rule to the hash table*/
                install_rule(rule);

                install_counter++;
            }
        } else
            LogMan::Msg::IFmt("Error in parsing rule file: {}.\n", line);
    }

    LogMan::Msg::IFmt("== Ready: {} translation rules loaded, {} installed, {} cached.\n\n", counter, install_counter, cache_counter);
    
    // 合并缓存规则表和普通规则表
    for (i = 0; i < MAX_GUEST_LEN;i++){
        if (cache_rule_table[i]){
            TranslationRule *temp = cache_rule_table[i];
            while(temp->next) {
                temp = temp->next;
            }
            temp->next = rule_table[i];
        } else {
            cache_rule_table[i] = rule_table[i];
        }

    }
}

// 打印规则命中次数（用于性能分析）
#ifdef PROFILE_RULE_TRANSLATION
void print_rule_hit_num(void );
void print_rule_hit_num(void)
{
    TranslationRule *cur_max;
    int zero_counter = 0;
    int counter[5] = {0};
    int i;
    
    for (i = 0; i < MAX_GUEST_LEN; i++) {
        TranslationRule *cur_rule = rule_table[i];
        while(cur_rule) {
            if (cur_rule->hit_num == 0)
                zero_counter++;
            cur_rule = cur_rule->next;
        }
    }

    LogMan::Msg::IFmt("Rule hit information: {} rules has zero hit.", zero_counter);
    LogMan::Msg::IFmt("Index  #Guest  #Hit");
    while(1) {
        cur_max = NULL;
        for (i = 0; i < MAX_GUEST_LEN; i++) {
            TranslationRule *cur_rule = rule_table[i];
            while(cur_rule) {
                if (cur_rule->print_flag == 0 &&
                    ((cur_max != NULL && cur_rule->hit_num > cur_max->hit_num) ||
                     (cur_max == NULL && cur_rule->hit_num > 0)))
                    cur_max = cur_rule;
                cur_rule = cur_rule->next;
            }
        }
        if (cur_max) {
            LogMan::Msg::IFmt( "  {}\t{}\t%llu",
                    cur_max->index, cur_max->guest_instr_num, cur_max->hit_num);
            cur_max->print_flag = 1;
            if (cur_max->guest_instr_num > 4)
                counter[4]++;
            else
                counter[cur_max->guest_instr_num-1]++;
        }
        else
            break;
    }
    LogMan::Msg::IFmt("#Guest    #RuleCounter");
    for (i = 0; i < 5; i++)
        if (i == 4)
            LogMan::Msg::IFmt( " >4           {}", counter[i]);
        else
            LogMan::Msg::IFmt( "  {}           {}", i+1, counter[i]);
}
#endif
