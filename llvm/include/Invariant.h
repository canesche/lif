//===-- Invariant.h ---------------------------------------------*- C++ -*-===//
// Copyright (C) 2020  Luigi D. C. Soares
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//===----------------------------------------------------------------------===//
///
/// \file
/// This file contains the declaration of the Invariant Pass, which transforms
/// some LLVM IR into a version that executes the same set of instructions
/// regardless of the inputs.
///
//===----------------------------------------------------------------------===//
#ifndef LLVM_LIF_INVARIANT_H
#define LLVM_LIF_INVARIANT_H

#include "Cond.h"

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Value.h>
#include <set>

namespace invariant {
/// A pass that transforms a function into an invariant version.
///
/// An invariant function executes the same set of instructions regardless of
/// its inputs. Hence, this property can be used, e.g., for the mitigation of
/// side channel leaks on a cryptography library.
///
/// Currently, this pass cannot handle functions contanining loops.
struct InvariantPass : public llvm::PassInfoMixin<InvariantPass> {
    /// Transforms \p F into an invariant version.
    ///
    /// \returns the set of analyses preserved after running this pass.
    /// PreservedAnalyses::all if something went wrong (e.g. trying to
    /// transform a function with loops); otherwise, PreservedAnalyses::none.
    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
};

class Transform {
  public:
    /// Constructor that takes a function \F and bind the proper conditions
    /// to its basic blocks.
    Transform(llvm::Function &F, const llvm::TargetLibraryInfo *TLI);

    /// Traverses the basic blocks of a function, applying the proper
    /// transformation to each instruction.
    void run();

    /// Transforms \p Phi into a set of instructions according to the incoming
    /// conditions of the basic block that contains \Phi.
    ///
    /// Note: If the transformation occurs, \p Phi is removed from the basic
    /// block.
    void phi(llvm::PHINode &Phi);

    /// Transforms \p Load into a set of instructions according to the incoming
    /// conditions of the basic block that contains \p Load.
    void load(llvm::LoadInst &Load);

    /// Transforms \p Store into a set of instructions according to the incoming
    /// conditions of the basic block that contains \p Store.
    void store(llvm::StoreInst &Store);

    /// Transforms \p GEP into a set of instructions according to \p NewCond, a
    /// condition associated with the new indices being accessed, and \p
    /// LastCond, a condition associated with the last used indices.
    void gep(llvm::GetElementPtrInst *GEP, llvm::Value *Cond);

  private:
    /// Map between basic blocks and incoming conditions required to apply the
    /// transform. rule to an instruction.
    cond::InMap InM;

    /// The function to be transformed.
    llvm::Function &F;

    /// A shadow memory address used to ensure the safety of accesses whenever
    /// those accesses surpass the limit given by some parameter S.
    llvm::AllocaInst *Shadow;

    /// Keep track of the size values associated with each ptr.
    llvm::DenseMap<const llvm::Value *, llvm::Value *> SizeM;

    /// Keep track of instructions that should not be transformed, like the
    /// ones generated by cond::bind.
    std::set<llvm::Value *> SkipS;

    // TODO: Move to another file? Utils? Make static?
    /// Given two values, \p VTrue and \p VFalse, and a condition \p Cond,
    /// generate instructions for selecting between \p VTrue and \p VFalse.
    ///
    /// \returns a value representing the selected one.
    llvm::Value *select(llvm::Value *Cond, llvm::Value *VTrue,
                        llvm::Value *VFalse, llvm::Instruction *Before);

    /// Given a basic block \p BB, find its incoming conditions and join them
    /// by applying the | (or) operator.
    ///
    /// This method requries a # of incoming conds > 0.
    /// The size of \p BB grows according to the # of instructions generated.
    ///
    /// \returns a list of generated instructions.
    llvm::SmallVector<llvm::Instruction *, 8> joinCond(llvm::BasicBlock &BB);
};
} // namespace invariant

#endif
