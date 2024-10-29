public:
  DEF_RV_OPC(Shifts) {
    RISCVOperand *opd0 = &instr->opd[0];
    RISCVOperand *opd1 = &instr->opd[1];
    RISCVOperand *opd2 = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvGPR(rvreg0);
    auto rs1 = GetRiscvGPR(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_IMM) {
        int32_t shamt = GetImmMapWrapper(&opd2->content.imm);

        // shamt[4:0], x86 shift > riscv shamt?
        if (instr->opc == RISCV_OPC_SLLI) {
            as->SLLI(rd, rs1, shamt);
        } else if (instr->opc == RISCV_OPC_SLLIW) {
            as->SLLIW(rd, rs1, shamt);
        } else if (instr->opc == RISCV_OPC_SRLI) {
            as->SRLI(rd, rs1, shamt);
        } else if (instr->opc == RISCV_OPC_SRLIW) {
            as->SRLIW(rd, rs1, shamt);
        } else if (instr->opc == RISCV_OPC_SRAI) {
            as->SRAI(rd, rs1, shamt);
        } else if (instr->opc == RISCV_OPC_SRAIW) {
            as->SRAIW(rd, rs1, shamt);
        }

    } else if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_REG) {

      if (opd2->content.reg.num != RISCV_REG_INVALID) {
        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rs2 = GetRiscvGPR(rvreg2);

        if (instr->opc == RISCV_OPC_SLL) {
            as->SLL(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_SLLW) {
            as->SLLW(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_SRL) {
            as->SRL(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_SRLW) {
            as->SRLW(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_SRA) {
            as->SRA(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_SRAW) {
            as->SRAW(rd, rs1, rs2);
        }

      } else
          LogMan::Msg::EFmt("[RISC-V] Unsupported reg for shift instruction.");

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for shift instruction.");
  }

  DEF_RV_OPC(ADD) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvGPR(rvreg0);
    auto rs1 = GetRiscvGPR(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_IMM) {
        int32_t Imm = GetImmMapWrapper(&opd2->content.imm);

        // I-immediate[11:0], x86 imm > riscv imm?
        if (instr->opc == RISCV_OPC_ADDI) {
          as->ADDI(rd, rs1, Imm);
        } else if (instr->opc == RISCV_OPC_MV) {
          as->ADDI(rd, rs1, 0);
        } else if (instr->opc == RISCV_OPC_ADDIW) {
          as->ADDIW(rd, rs1, Imm);
        }

    } else if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_REG) {

      if (opd2->content.reg.num != RISCV_REG_INVALID) {
        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rs2 = GetRiscvGPR(rvreg2);

        if (instr->opc == RISCV_OPC_ADD) {
            as->ADD(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_ADDW) {
            as->ADDW(rd, rs1, rs2);
        }
      } else
          LogMan::Msg::EFmt("[RISC-V] Unsupported reg for ADD instruction.");

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for ADD instruction.");
  }

  DEF_RV_OPC(LI) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rd = GetRiscvGPR(rvreg0);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG) {
        int32_t Imm = GetImmMapWrapper(&opd1->content.imm);
        // I-immediate[11:0], x86 imm > riscv imm?
        as->LI(rd, Imm);
    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for LI instruction.");
  }

  DEF_RV_OPC(SUB) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvGPR(rvreg0);
    auto rs1 = GetRiscvGPR(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_REG) {

      if (opd2->content.reg.num != RISCV_REG_INVALID) {
        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rs2 = GetRiscvGPR(rvreg2);

        // CF Flag?
        if (instr->opc == RISCV_OPC_SUB) {
            as->SUB(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_SUBW) {
            as->SUBW(rd, rs1, rs2);
        }
      } else
          LogMan::Msg::EFmt("[RISC-V] Unsupported reg for sub instruction.");

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for sub instruction.");
  }

  DEF_RV_OPC(LUI) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rd = GetRiscvGPR(rvreg0);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_IMM) {
        int32_t Imm = GetImmMapWrapper(&opd1->content.imm);

        // I-immediate[11:0]
        if (instr->opc == RISCV_OPC_LUI) {
          as->LUI(rd, Imm);
        } else if (instr->opc == RISCV_OPC_AUIPC) {
          as->AUIPC(rd, Imm);
        }

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for LUI instruction.");
  }

  DEF_RV_OPC(Logical) {
    RISCVOperand *opd0 = &instr->opd[0];
    RISCVOperand *opd1 = &instr->opd[1];
    RISCVOperand *opd2 = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvGPR(rvreg0);
    auto rs1 = GetRiscvGPR(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_IMM) {
        int32_t imm = GetImmMapWrapper(&opd2->content.imm);

        // I-immediate[11:0], x86 imm > riscv imm?
        if (instr->opc == RISCV_OPC_XORI) {
            as->XORI(rd, rs1, imm);
        } else if (instr->opc == RISCV_OPC_ORI) {
            as->ORI(rd, rs1, imm);
        } else if (instr->opc == RISCV_OPC_ANDI) {
            as->ANDI(rd, rs1, imm);
        }

    } else if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_REG) {

      if (opd2->content.reg.num != RISCV_REG_INVALID) {
        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rs2 = GetRiscvGPR(rvreg2);

        if (instr->opc == RISCV_OPC_XOR) {
            as->XOR(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_OR) {
            as->OR(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_AND) {
            as->AND(rd, rs1, rs2);
        }

      } else
          LogMan::Msg::EFmt("[RISC-V] Unsupported reg for Logical instruction.");

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Logical instruction.");
  }

  DEF_RV_OPC(Compare) {
    RISCVOperand *opd0 = &instr->opd[0];
    RISCVOperand *opd1 = &instr->opd[1];
    RISCVOperand *opd2 = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvGPR(rvreg0);
    auto rs1 = GetRiscvGPR(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_IMM) {
        int32_t imm = GetImmMapWrapper(&opd2->content.imm);

        // I-immediate[11:0], x86 imm > riscv imm?
        if (instr->opc == RISCV_OPC_SLTI) {
            as->SLTI(rd, rs1, imm);
        } else if (instr->opc == RISCV_OPC_SLTIU) {
            as->SLTIU(rd, rs1, imm);
        }

    } else if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_REG) {

      if (opd2->content.reg.num != RISCV_REG_INVALID) {
        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rs2 = GetRiscvGPR(rvreg2);

        if (instr->opc == RISCV_OPC_SLT) {
            as->SLT(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_SLTU) {
            as->SLTU(rd, rs1, rs2);
        }

      } else
          LogMan::Msg::EFmt("[RISC-V] Unsupported reg for Compare instruction.");

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Compare instruction.");
  }

  DEF_RV_OPC(Branch) {
    RISCVOperand *opd0 = &instr->opd[0];
    RISCVOperand *opd1 = &instr->opd[1];
    RISCVOperand *opd2 = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rd = GetRiscvGPR(rvreg0);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_IMM) {
        int32_t imm = GetImmMapWrapper(&opd1->content.imm);

        if (instr->opc == RISCV_OPC_BLTZ) {
            as->BLTZ(rd, imm);
        } else if (instr->opc == RISCV_OPC_BLEZ) {
            as->BLEZ(rd, imm);
        } else if (instr->opc == RISCV_OPC_BGEZ) {
            as->BGEZ(rd, imm);
        } else if (instr->opc == RISCV_OPC_BGTZ) {
            as->BGTZ(rd, imm);
        } else if (instr->opc == RISCV_OPC_BNEZ) {
            as->BNEZ(rd, imm);
        }

    } else if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_IMM) {
        auto rvreg1 = GetRiscvReg(opd1->content.reg.num);
        auto rs1 = GetRiscvGPR(rvreg1);
        int32_t imm = GetImmMapWrapper(&opd2->content.imm);

        // I-immediate[11:0], x86 imm > riscv imm?
        if (instr->opc == RISCV_OPC_BEQ) {
            as->BEQ(rd, rs1, imm);
        } else if (instr->opc == RISCV_OPC_BNE) {
            as->BNE(rd, rs1, imm);
        } else if (instr->opc == RISCV_OPC_BLT) {
            as->BLT(rd, rs1, imm);
        } else if (instr->opc == RISCV_OPC_BLE) {
            as->BLE(rd, rs1, imm);
        } else if (instr->opc == RISCV_OPC_BGT) {
            as->BGT(rd, rs1, imm);
        } else if (instr->opc == RISCV_OPC_BGE) {
            as->BGE(rd, rs1, imm);
        } else if (instr->opc == RISCV_OPC_BLTU) {
            as->BLTU(rd, rs1, imm);
        } else if (instr->opc == RISCV_OPC_BGEU) {
            as->BGEU(rd, rs1, imm);
        }

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Branch instruction.");
  }

  DEF_RV_OPC(Load) {
    RISCVOperand *opd0 = &instr->opd[0];
    RISCVOperand *opd1 = &instr->opd[1];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rd = GetRiscvGPR(rvreg0);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_MEM) {
        auto rvreg1 = GetRiscvReg(opd1->content.mem.base);
        auto rs1 = GetRiscvGPR(rvreg1);
        int32_t imm = GetImmMapWrapper(&opd1->content.mem.offset);

        // I-immediate[11:0], x86 imm > riscv imm?
        if (instr->opc == RISCV_OPC_LB) {
            as->LB(rd, imm, rs1);
        } else if (instr->opc == RISCV_OPC_LH) {
            as->LH(rd, imm, rs1);
        } else if (instr->opc == RISCV_OPC_LHU) {
            as->LHU(rd, imm, rs1);
        } else if (instr->opc == RISCV_OPC_LW) {
            as->LW(rd, imm, rs1);
        } else if (instr->opc == RISCV_OPC_LWU) {
            as->LWU(rd, imm, rs1);
        } else if (instr->opc == RISCV_OPC_LD) {
            as->LD(rd, imm, rs1);
        }

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Load instruction.");
  }

  DEF_RV_OPC(Store) {
    RISCVOperand *opd0 = &instr->opd[0];
    RISCVOperand *opd1 = &instr->opd[1];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rd = GetRiscvGPR(rvreg0);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_MEM) {
        auto rvreg1 = GetRiscvReg(opd1->content.mem.base);
        auto rs1 = GetRiscvGPR(rvreg1);
        int32_t imm = GetImmMapWrapper(&opd1->content.mem.offset);

        // I-immediate[11:0], x86 imm > riscv imm?
        if (instr->opc == RISCV_OPC_SB) {
            as->SB(rd, imm, rs1);
        } else if (instr->opc == RISCV_OPC_SH) {
            as->SH(rd, imm, rs1);
        } else if (instr->opc == RISCV_OPC_SW) {
            as->SW(rd, imm, rs1);
        } else if (instr->opc == RISCV_OPC_SD) {
            as->SD(rd, imm, rs1);
        }

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Store instruction.");
  }

  DEF_RV_OPC(Jump) {
    RISCVOperand *opd0 = &instr->opd[0];
    RISCVOperand *opd1 = &instr->opd[1];
    RISCVOperand *opd2 = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rd = GetRiscvGPR(rvreg0);

    int32_t target, fallthrough;

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_IMM) {
        // I-immediate[11:0], x86 imm > riscv imm?
        if (instr->opc == RISCV_OPC_JAL) {
            // get new rip
            GetLabelMap(opd1->content.imm.content.sym, &target, &fallthrough);
            as->JAL(rd, fallthrough + target);
        }

    } else if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_IMM) {
        // I-immediate[11:0], x86 imm > riscv imm?
        if (instr->opc == RISCV_OPC_JALR) {
            auto rvreg1 = GetRiscvReg(opd1->content.reg.num);
            auto rs1 = GetRiscvGPR(rvreg1);

            GetLabelMap(opd2->content.imm.content.sym, &target, &fallthrough);
            as->JALR(rd, fallthrough + target, rs1);
        }

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Jump instruction.");
  }

  DEF_RV_OPC(Multiply) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvGPR(rvreg0);
    auto rs1 = GetRiscvGPR(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_REG) {

      if (opd2->content.reg.num != RISCV_REG_INVALID) {
        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rs2 = GetRiscvGPR(rvreg2);

        if (instr->opc == RISCV_OPC_MUL) {
            as->MUL(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_MULH) {
            as->MULH(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_MULW) {
            as->MULW(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_MULHSU) {
            as->MULHSU(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_MULHU) {
            as->MULHU(rd, rs1, rs2);
        }

      } else
          LogMan::Msg::EFmt("[RISC-V] Unsupported reg for Multiply instruction.");

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Multiply instruction.");
  }

  DEF_RV_OPC(Divide) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvGPR(rvreg0);
    auto rs1 = GetRiscvGPR(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_REG) {

      if (opd2->content.reg.num != RISCV_REG_INVALID) {
        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rs2 = GetRiscvGPR(rvreg2);

        if (instr->opc == RISCV_OPC_DIV) {
            as->DIV(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_DIVU) {
            as->DIVU(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_DIVW) {
            as->DIVW(rd, rs1, rs2);
        }

      } else
          LogMan::Msg::EFmt("[RISC-V] Unsupported reg for Divide instruction.");

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Divide instruction.");
  }

  DEF_RV_OPC(Remainder) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvGPR(rvreg0);
    auto rs1 = GetRiscvGPR(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_REG) {

      if (opd2->content.reg.num != RISCV_REG_INVALID) {
        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rs2 = GetRiscvGPR(rvreg2);

        if (instr->opc == RISCV_OPC_REM) {
            as->REM(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_REMU) {
            as->REMU(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_REMW) {
            as->REMW(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_REMUW) {
            as->REMUW(rd, rs1, rs2);
        }

      } else
          LogMan::Msg::EFmt("[RISC-V] Unsupported reg for Remainder instruction.");

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Remainder instruction.");
  }