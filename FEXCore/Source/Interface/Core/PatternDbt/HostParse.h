#ifndef ARM_PARSE_H
#define ARM_PARSE_H

#include "rule-translate.h"

void RuleArmInstrBufInit(void);

void RuleRiscvInstrBufInit(void);

bool ParseRuleHostCode(int arch, FILE *fp, TranslationRule *rule);

#endif
