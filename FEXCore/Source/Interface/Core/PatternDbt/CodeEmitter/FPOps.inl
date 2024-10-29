public:
/*
  RISC-V Flaoting-Point Extenssions: RVF & RVD
*/
  DEF_RV_OPC(FMV) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG) {

        if (instr->opc == RISCV_OPC_FMV_W_X) {
            auto rd = GetRiscvFPR(rvreg0);
            auto rs1 = GetRiscvGPR(rvreg1);
            as->FMV_W_X(rd, rs1);
        } else if (instr->opc == RISCV_OPC_FMV_H_X) {
            auto rd = GetRiscvFPR(rvreg0);
            auto rs1 = GetRiscvGPR(rvreg1);
            as->FMV_H_X(rd, rs1);
        } else if (instr->opc == RISCV_OPC_FMV_D_X) {
            auto rd = GetRiscvFPR(rvreg0);
            auto rs1 = GetRiscvGPR(rvreg1);
            as->FMV_D_X(rd, rs1);
        } else if (instr->opc == RISCV_OPC_FMV_X_W) {
            auto rd = GetRiscvGPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FMV_X_W(rd, rs1);
        } else if (instr->opc == RISCV_OPC_FMV_X_H) {
            auto rd = GetRiscvGPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FMV_X_H(rd, rs1);
        } else if (instr->opc == RISCV_OPC_FMV_X_D) {
            auto rd = GetRiscvGPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FMV_X_D(rd, rs1);
        }

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for FMV instruction.");
  }

  DEF_RV_OPC(FCVT) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG) {

        if (instr->opc == RISCV_OPC_FCVT_S_W) {
            auto rd = GetRiscvFPR(rvreg0);
            auto rs1 = GetRiscvGPR(rvreg1);
            as->FCVT_S_W(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_S_WU) {
            auto rd = GetRiscvFPR(rvreg0);
            auto rs1 = GetRiscvGPR(rvreg1);
            as->FCVT_S_WU(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_S_H) {
            auto rd = GetRiscvFPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FCVT_S_H(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_S_D) {
            auto rd = GetRiscvFPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FCVT_S_D(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_S_L) {
            auto rd = GetRiscvFPR(rvreg0);
            auto rs1 = GetRiscvGPR(rvreg1);
            as->FCVT_S_L(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_S_LU) {
            auto rd = GetRiscvFPR(rvreg0);
            auto rs1 = GetRiscvGPR(rvreg1);
            as->FCVT_S_LU(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_D_S) {
            auto rd = GetRiscvFPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FCVT_D_S(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_D_W) {
            auto rd = GetRiscvFPR(rvreg0);
            auto rs1 = GetRiscvGPR(rvreg1);
            as->FCVT_D_W(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_D_WU) {
            auto rd = GetRiscvFPR(rvreg0);
            auto rs1 = GetRiscvGPR(rvreg1);
            as->FCVT_D_WU(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_D_L) {
            auto rd = GetRiscvFPR(rvreg0);
            auto rs1 = GetRiscvGPR(rvreg1);
            as->FCVT_D_L(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_D_LU) {
            auto rd = GetRiscvFPR(rvreg0);
            auto rs1 = GetRiscvGPR(rvreg1);
            as->FCVT_D_LU(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_D_H) {
            auto rd = GetRiscvFPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FCVT_D_H(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_W_S) {
            auto rd = GetRiscvGPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FCVT_W_S(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_W_H) {
            auto rd = GetRiscvGPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FCVT_W_H(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_W_D) {
            auto rd = GetRiscvGPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FCVT_W_D(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_WU_S) {
            auto rd = GetRiscvGPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FCVT_WU_S(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_WU_H) {
            auto rd = GetRiscvGPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FCVT_WU_H(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_WU_D) {
            auto rd = GetRiscvGPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FCVT_WU_D(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_L_S) {
            auto rd = GetRiscvGPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FCVT_W_S(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_L_H) {
            auto rd = GetRiscvGPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FCVT_W_H(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_L_D) {
            auto rd = GetRiscvGPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FCVT_W_D(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_LU_S) {
            auto rd = GetRiscvGPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FCVT_WU_S(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_LU_H) {
            auto rd = GetRiscvGPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FCVT_WU_H(rd, rs1, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FCVT_LU_D) {
            auto rd = GetRiscvGPR(rvreg0);
            auto rs1 = GetRiscvFPR(rvreg1);
            as->FCVT_WU_D(rd, rs1, biscuit::RMode::DYN);
        }

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for FCVT instruction.");
  }

  DEF_RV_OPC(FLoad) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rd = GetRiscvFPR(rvreg0);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_MEM) {
        auto rvreg1 = GetRiscvReg(opd1->content.mem.base);
        auto rs1 = GetRiscvGPR(rvreg1);
        int32_t imm = GetImmMapWrapper(&opd1->content.mem.offset);

        if (instr->opc == RISCV_OPC_FLW) {
            as->FLW(rd, imm, rs1);
        } else if (instr->opc == RISCV_OPC_FLD) {
            as->FLD(rd, imm, rs1);
        } else if (instr->opc == RISCV_OPC_FSW) {
            as->FSW(rd, imm, rs1);
        } else if (instr->opc == RISCV_OPC_FSD) {
            as->FSD(rd, imm, rs1);
        }

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for FLoad instruction.");
  }

  DEF_RV_OPC(FStore) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rd = GetRiscvFPR(rvreg0);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_MEM) {
        auto rvreg1 = GetRiscvReg(opd1->content.mem.base);
        auto rs1 = GetRiscvGPR(rvreg1);
        int32_t imm = GetImmMapWrapper(&opd1->content.mem.offset);

        if (instr->opc == RISCV_OPC_FSW) {
            as->FSW(rd, imm, rs1);
        } else if (instr->opc == RISCV_OPC_FSD) {
            as->FSD(rd, imm, rs1);
        }

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for FStore instruction.");
  }

  DEF_RV_OPC(FADD) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvFPR(rvreg0);
    auto rs1 = GetRiscvFPR(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_REG) {

      if (opd2->content.reg.num != RISCV_REG_INVALID) {
        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rs2 = GetRiscvFPR(rvreg2);

        if (instr->opc == RISCV_OPC_FADD_S) {
            as->FADD_S(rd, rs1, rs2, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FADD_H) {
            as->FADD_H(rd, rs1, rs2, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FADD_D) {
            as->FADD_D(rd, rs1, rs2, biscuit::RMode::DYN);
        }

      } else
          LogMan::Msg::EFmt("[RISC-V] Unsupported reg for Remainder instruction.");

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Remainder instruction.");
  }

  DEF_RV_OPC(FSUB) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvFPR(rvreg0);
    auto rs1 = GetRiscvFPR(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_REG) {

      if (opd2->content.reg.num != RISCV_REG_INVALID) {
        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rs2 = GetRiscvFPR(rvreg2);

        if (instr->opc == RISCV_OPC_FSUB_S) {
            as->FSUB_S(rd, rs1, rs2, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FSUB_H) {
            as->FSUB_H(rd, rs1, rs2, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FSUB_D) {
            as->FSUB_D(rd, rs1, rs2, biscuit::RMode::DYN);
        }

      } else
          LogMan::Msg::EFmt("[RISC-V] Unsupported reg for Remainder instruction.");

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Remainder instruction.");
  }

  DEF_RV_OPC(FMUL) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvFPR(rvreg0);
    auto rs1 = GetRiscvFPR(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_REG) {

      if (opd2->content.reg.num != RISCV_REG_INVALID) {
        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rs2 = GetRiscvFPR(rvreg2);

        if (instr->opc == RISCV_OPC_FMUL_S) {
            as->FMUL_S(rd, rs1, rs2, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FMUL_H) {
            as->FMUL_H(rd, rs1, rs2, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FMUL_D) {
            as->FMUL_D(rd, rs1, rs2, biscuit::RMode::DYN);
        }

      } else
          LogMan::Msg::EFmt("[RISC-V] Unsupported reg for MUL instruction.");

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for MUL instruction.");
  }

  DEF_RV_OPC(FDIV) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvFPR(rvreg0);
    auto rs1 = GetRiscvFPR(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG && opd2->type == RISCV_OPD_TYPE_REG) {

      if (opd2->content.reg.num != RISCV_REG_INVALID) {
        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rs2 = GetRiscvFPR(rvreg2);

        if (instr->opc == RISCV_OPC_FDIV_S) {
            as->FDIV_S(rd, rs1, rs2, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FDIV_H) {
            as->FDIV_H(rd, rs1, rs2, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FDIV_D) {
            as->FDIV_D(rd, rs1, rs2, biscuit::RMode::DYN);
        }

      } else
          LogMan::Msg::EFmt("[RISC-V] Unsupported reg for DIV instruction.");

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for DIV instruction.");
  }

  DEF_RV_OPC(FMulAdd) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];
    RISCVOperand *opd3   = &instr->opd[3];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvFPR(rvreg0);
    auto rs1 = GetRiscvFPR(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG
      && opd2->type == RISCV_OPD_TYPE_REG && opd3->type == RISCV_OPD_TYPE_REG) {

        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rvreg3 = GetRiscvReg(opd3->content.reg.num);

        auto rs2 = GetRiscvFPR(rvreg2);
        auto rs3 = GetRiscvFPR(rvreg3);

        if (instr->opc == RISCV_OPC_FMADD_S) {
            as->FMADD_S(rd, rs1, rs2, rs3, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FMADD_H) {
            as->FMADD_H(rd, rs1, rs2, rs3, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FMADD_D) {
            as->FMADD_D(rd, rs1, rs2, rs3, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FMSUB_S) {
            as->FMSUB_S(rd, rs1, rs2, rs3, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FMSUB_H) {
            as->FMSUB_H(rd, rs1, rs2, rs3, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FMSUB_D) {
            as->FMSUB_D(rd, rs1, rs2, rs3, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FNMSUB_S) {
            as->FNMSUB_S(rd, rs1, rs2, rs3, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FNMSUB_H) {
            as->FNMSUB_H(rd, rs1, rs2, rs3, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FNMSUB_D) {
            as->FNMSUB_D(rd, rs1, rs2, rs3, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FNMADD_S) {
            as->FNMADD_S(rd, rs1, rs2, rs3, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FNMADD_H) {
            as->FNMADD_H(rd, rs1, rs2, rs3, biscuit::RMode::DYN);
        } else if (instr->opc == RISCV_OPC_FNMADD_D) {
            as->FNMADD_D(rd, rs1, rs2, rs3, biscuit::RMode::DYN);
        }

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Mul-Add instruction.");
  }

  DEF_RV_OPC(FSignInject) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvFPR(rvreg0);
    auto rs1 = GetRiscvFPR(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG
      && opd2->type == RISCV_OPD_TYPE_REG) {

        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rs2 = GetRiscvFPR(rvreg2);

        if (instr->opc == RISCV_OPC_FSGNJ_S) {
            as->FSGNJ_S(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FSGNJ_H) {
            as->FSGNJ_H(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FSGNJ_D) {
            as->FSGNJ_D(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FSGNJN_S) {
            as->FSGNJN_S(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FSGNJN_H) {
            as->FSGNJN_H(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FSGNJN_D) {
            as->FSGNJN_D(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FSGNJX_S) {
            as->FSGNJX_S(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FSGNJX_H) {
            as->FSGNJX_H(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FSGNJX_D) {
            as->FSGNJX_D(rd, rs1, rs2);
        }

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Sign Inject instruction.");
  }

  DEF_RV_OPC(FMINMAX) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvFPR(rvreg0);
    auto rs1 = GetRiscvFPR(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG
      && opd2->type == RISCV_OPD_TYPE_REG) {

        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rs2 = GetRiscvFPR(rvreg2);

        if (instr->opc == RISCV_OPC_FMIN_S) {
            as->FMIN_S(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FMIN_H) {
            as->FMIN_H(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FMIN_D) {
            as->FMIN_D(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FMAX_S) {
            as->FMAX_S(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FMAX_H) {
            as->FMAX_H(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FMAX_D) {
            as->FMAX_D(rd, rs1, rs2);
        }

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for MAX MIN instruction.");
  }

  DEF_RV_OPC(FCompare) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvGPR(rvreg0);
    auto rs1 = GetRiscvFPR(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG
      && opd2->type == RISCV_OPD_TYPE_REG) {

        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rs2 = GetRiscvFPR(rvreg2);

        if (instr->opc == RISCV_OPC_FEQ_S) {
            as->FEQ_S(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FEQ_H) {
            as->FEQ_H(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FEQ_D) {
            as->FEQ_D(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FLT_S) {
            as->FLT_S(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FLT_H) {
            as->FLT_H(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FLT_D) {
            as->FLT_D(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FLE_S) {
            as->FLE_S(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FLE_H) {
            as->FLE_H(rd, rs1, rs2);
        } else if (instr->opc == RISCV_OPC_FLE_D) {
            as->FLE_D(rd, rs1, rs2);
        }

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Compare instruction.");
  }