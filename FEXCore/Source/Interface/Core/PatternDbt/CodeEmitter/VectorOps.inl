public:
  DEF_RV_OPC(VSET) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvGPR(rvreg0);
    auto rs1 = GetRiscvGPR(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG
      && opd2->type == RISCV_OPD_TYPE_REG) {
        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rs2 = GetRiscvGPR(rvreg2);

        if (instr->opc == RISCV_OPC_VSETVL) {
          as->VSETVL(rd, rs1, rs2);
        }

    } else if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG
      && opd2->type == RISCV_OPD_TYPE_IMM) {
        int32_t imm = GetImmMapWrapper(&opd2->content.imm);

        if (instr->opc == RISCV_OPC_VSETVLI) {
          as->VSETVLI(rd, rs1, biscuit::SEW::E8, biscuit::LMUL::M1, biscuit::VTA::No, biscuit::VMA::No);
        }

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for SET VECTOR LEN instruction.");
  }

  DEF_RV_OPC(VMulDiv) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvVec(rvreg0);
    auto rs1 = GetRiscvVec(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG
      && opd2->type == RISCV_OPD_TYPE_REG) {

        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);
        auto rs2 = GetRiscvVec(rvreg2);

        if (instr->opc == RISCV_OPC_VMULH) {
            as->VMULH(rd, rs1, rs2, biscuit::VecMask::No);
        } else if (instr->opc == RISCV_OPC_VREM) {
            as->VREM(rd, rs1, rs2, biscuit::VecMask::No);
        }

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Multiply-Divide instruction.");
  }

  DEF_RV_OPC(VShifts) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvVec(rvreg0);
    auto rs1 = GetRiscvVec(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG
      && opd2->type == RISCV_OPD_TYPE_REG) {

        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);

        if (rvreg2 >= RISCV_REG_X0 && rvreg2 <= RISCV_REG_X31) {
          auto rs2 = GetRiscvGPR(rvreg2);
          if (instr->opc == RISCV_OPC_VSLL) {
            as->VSLL(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VSRL) {
            as->VSRL(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VSRA) {
            as->VSRA(rd, rs1, rs2, biscuit::VecMask::No);
          }
        } else if (rvreg2 >= RISCV_REG_V0 && rvreg2 <= RISCV_REG_V31) {
          auto rs2 = GetRiscvVec(rvreg2);
          if (instr->opc == RISCV_OPC_VSLL) {
            as->VSLL(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VSRL) {
            as->VSRL(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VSRA) {
            as->VSRA(rd, rs1, rs2, biscuit::VecMask::No);
          }
        }

    } else if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG
      && opd2->type == RISCV_OPD_TYPE_IMM) {
        // I-immediate[11:0], x86 imm > riscv imm?
        int32_t imm = GetImmMapWrapper(&opd2->content.imm);
        if (instr->opc == RISCV_OPC_VSLL) {
          as->VSLL(rd, rs1, imm, biscuit::VecMask::No);
        } else if (instr->opc == RISCV_OPC_VSRL) {
          as->VSRL(rd, rs1, imm, biscuit::VecMask::No);
        } else if (instr->opc == RISCV_OPC_VSRA) {
          as->VSRA(rd, rs1, imm, biscuit::VecMask::No);
        }
    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for SET VECTOR LEN instruction.");
  }

  DEF_RV_OPC(VMV) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG) {
        if (instr->opc == RISCV_OPC_VMV) {
          auto rd = GetRiscvVec(rvreg0);
          auto rvreg1 = GetRiscvReg(opd1->content.reg.num);
          if (rvreg1 >= RISCV_REG_X0 && rvreg1 <= RISCV_REG_X31) {
            auto rs1 = GetRiscvGPR(rvreg1);
            as->VMV(rd, rs1);
          } else if (rvreg1 >= RISCV_REG_V0 && rvreg1 <= RISCV_REG_V31) {
            auto rs1 = GetRiscvVec(rvreg1);
            as->VMV(rd, rs1);
          }
        } else if (instr->opc == RISCV_OPC_VMV_XS) {
          auto rd = GetRiscvGPR(rvreg0);
          auto rvreg1 = GetRiscvReg(opd1->content.reg.num);
          auto rs1 = GetRiscvVec(rvreg1);
          as->VMV_XS(rd, rs1);
        }
    } else if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_IMM) {
        auto rd = GetRiscvVec(rvreg0);
        int32_t imm = GetImmMapWrapper(&opd1->content.imm);
        if (instr->opc == RISCV_OPC_VMV) {
          as->VMV(rd, imm);
        }
    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for SET VECTOR LEN instruction.");
  }

  DEF_RV_OPC(VArithmetic) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvVec(rvreg0);
    auto rs1 = GetRiscvVec(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG
      && opd2->type == RISCV_OPD_TYPE_REG) {

        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);

        if (rvreg2 >= RISCV_REG_X0 && rvreg2 <= RISCV_REG_X31) {
          auto rs2 = GetRiscvGPR(rvreg2);
          if (instr->opc == RISCV_OPC_VADD) {
            as->VADD(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VSUB_VX) {
            as->VSUB(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VMUL) {
            as->VMUL(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VDIV) {
            as->VDIV(rd, rs1, rs2, biscuit::VecMask::No);
          }
        } else if (rvreg2 >= RISCV_REG_V0 && rvreg2 <= RISCV_REG_V31) {
          auto rs2 = GetRiscvVec(rvreg2);
          if (instr->opc == RISCV_OPC_VADD) {
            as->VADD(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VSUB_VV) {
            as->VSUB(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VMUL) {
            as->VMUL(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VDIV) {
            as->VDIV(rd, rs1, rs2, biscuit::VecMask::No);
          }
        }

    } else if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG
      && opd2->type == RISCV_OPD_TYPE_IMM) {
        // I-immediate[11:0], x86 imm > riscv imm?
        int32_t imm = GetImmMapWrapper(&opd2->content.imm);
        if (instr->opc == RISCV_OPC_VADD) {
          as->VADD(rd, rs1, imm, biscuit::VecMask::No);
        }
    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Arithmetic instruction.");
  }

  DEF_RV_OPC(VMulAdd) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg2 = GetRiscvReg(opd2->content.reg.num);

    auto rd = GetRiscvVec(rvreg0);
    auto rs2 = GetRiscvVec(rvreg2);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG
      && opd2->type == RISCV_OPD_TYPE_REG) {

        auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

        if (rvreg1 >= RISCV_REG_F0 && rvreg1 <= RISCV_REG_F31) {
          auto rs1 = GetRiscvFPR(rvreg1);
          if (instr->opc == RISCV_OPC_VFMADD) {
            as->VFMADD(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VFMSUB) {
            as->VFMSUB(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VFNMADD) {
            as->VFNMADD(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VFNMSUB) {
            as->VFNMSUB(rd, rs1, rs2, biscuit::VecMask::No);
          }
        } else if (rvreg1 >= RISCV_REG_V0 && rvreg1 <= RISCV_REG_V31) {
          auto rs1 = GetRiscvVec(rvreg1);
          if (instr->opc == RISCV_OPC_VFMADD) {
            as->VFMADD(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VFMSUB) {
            as->VFMSUB(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VFNMADD) {
            as->VFNMADD(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VFNMSUB) {
            as->VFNMSUB(rd, rs1, rs2, biscuit::VecMask::No);
          }
        }

    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Multiply ADD instruction.");
  }

  DEF_RV_OPC(VMAXMIN) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvVec(rvreg0);
    auto rs1 = GetRiscvVec(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG
      && opd2->type == RISCV_OPD_TYPE_REG) {

        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);

        if (rvreg2 >= RISCV_REG_X0 && rvreg2 <= RISCV_REG_X31) {
          auto rs2 = GetRiscvGPR(rvreg2);
          if (instr->opc == RISCV_OPC_VMAX) {
            as->VMAX(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VMIN) {
            as->VMIN(rd, rs1, rs2, biscuit::VecMask::No);
          }
        } else if (rvreg2 >= RISCV_REG_V0 && rvreg2 <= RISCV_REG_V31) {
          auto rs2 = GetRiscvVec(rvreg2);
          if (instr->opc == RISCV_OPC_VMAX) {
            as->VMAX(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VMIN) {
            as->VMIN(rd, rs1, rs2, biscuit::VecMask::No);
          }
        }
    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Vector MAX MIN instruction.");
  }

  DEF_RV_OPC(VLogical) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];
    RISCVOperand *opd2   = &instr->opd[2];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rvreg1 = GetRiscvReg(opd1->content.reg.num);

    auto rd = GetRiscvVec(rvreg0);
    auto rs1 = GetRiscvVec(rvreg1);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG
      && opd2->type == RISCV_OPD_TYPE_REG) {

        auto rvreg2 = GetRiscvReg(opd2->content.reg.num);

        if (rvreg2 >= RISCV_REG_X0 && rvreg2 <= RISCV_REG_X31) {
          auto rs2 = GetRiscvGPR(rvreg2);
          if (instr->opc == RISCV_OPC_VXOR) {
            as->VXOR(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VOR) {
            as->VOR(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VAND) {
            as->VAND(rd, rs1, rs2, biscuit::VecMask::No);
          }
        } else if (rvreg2 >= RISCV_REG_V0 && rvreg2 <= RISCV_REG_V31) {
          auto rs2 = GetRiscvVec(rvreg2);
          if (instr->opc == RISCV_OPC_VXOR) {
            as->VXOR(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VOR) {
            as->VOR(rd, rs1, rs2, biscuit::VecMask::No);
          } else if (instr->opc == RISCV_OPC_VAND) {
            as->VAND(rd, rs1, rs2, biscuit::VecMask::No);
          }
        }

    } else if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG
      && opd2->type == RISCV_OPD_TYPE_IMM) {
        // I-immediate[11:0], x86 imm > riscv imm?
        int32_t imm = GetImmMapWrapper(&opd2->content.imm);
        if (instr->opc == RISCV_OPC_VXOR) {
          as->VXOR(rd, rs1, imm, biscuit::VecMask::No);
        } else if (instr->opc == RISCV_OPC_VOR) {
          as->VOR(rd, rs1, imm, biscuit::VecMask::No);
        } else if (instr->opc == RISCV_OPC_VAND) {
          as->VAND(rd, rs1, imm, biscuit::VecMask::No);
        }
    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for Logical instruction.");
  }

  DEF_RV_OPC(VMSBF) {
    RISCVOperand *opd0   = &instr->opd[0];
    RISCVOperand *opd1   = &instr->opd[1];

    auto rvreg0 = GetRiscvReg(opd0->content.reg.num);
    auto rd = GetRiscvVec(rvreg0);

    if (opd0->type == RISCV_OPD_TYPE_REG && opd1->type == RISCV_OPD_TYPE_REG) {
        auto rvreg1 = GetRiscvReg(opd1->content.reg.num);
        auto rs1 = GetRiscvVec(rvreg1);
        as->VMSBF(rd, rs1, biscuit::VecMask::No);
    } else
        LogMan::Msg::EFmt("[RISC-V] Unsupported operand type for SET VECTOR LEN instruction.");
  }