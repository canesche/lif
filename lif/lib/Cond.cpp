//===-- Cond.cpp ----------------------------------------------------------===//
// Copyright (C) 2020  Luigi D. C. Soares
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//===----------------------------------------------------------------------===//
///
/// \file
/// This file contains the implementation of the functions related to both
/// incoming and outgoing conditions of some basic block.
///
//===----------------------------------------------------------------------===//

#include "Cond.h"

#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/Support/Casting.h>

using namespace lif;

OutMap lif::allocOut(llvm::Function &F, const LoopWrapper &LW,
                     const llvm::DenseSet<llvm::Value *> &Tainted) {
    OutMap OM(F.size());
    auto InsertionPoint = &*F.getEntryBlock().getFirstInsertionPt();
    auto BoolTy = llvm::IntegerType::getInt1Ty(F.getContext());

    // Allocate an outgoing variable for every basic block in F.
    for (auto &BB : F) {
        auto Out = new llvm::AllocaInst(BoolTy, 0, "out.", InsertionPoint);
        auto Freezed =
            LW.ExitingBlocks.contains(&BB) &&
                    Tainted.contains(BB.getTerminator())
                ? new llvm::AllocaInst(BoolTy, 0, "out.freezed", InsertionPoint)
                : nullptr;
        OM[&BB] = {Out, Freezed};
    }

    return OM;
}

std::pair<Incoming, llvm::SmallVector<llvm::Instruction *, 4>>
lif::bindIn(llvm::BasicBlock &BB, const OutMap OM, const LoopWrapper &LW,
            const llvm::DenseSet<llvm::Value *> &Tainted) {
    Incoming In;
    llvm::SmallVector<llvm::Instruction *, 4> MemInsts;
    auto LatchEnd = LW.Latches.end();

    for (auto Pred : predecessors(&BB)) {
        auto T = Pred->getTerminator();
        auto Branch = llvm::dyn_cast<llvm::BranchInst>(T);

        // TODO: Handle switch, etc...
        if (!Branch) continue;

        // Get the address of the instruction associated with the first
        // insertion pointer.
        auto InsertionPoint = BB.getFirstNonPHI();

        // Out map must have been constructed already; thus, every
        // basic block should be associated with an out variable. In the case of
        // loop exiting edges that are tainted, we consider the freezed outgoing
        // condition.
        auto OutPtr = LW.ExitBlocks.contains(&BB) &&
                              LW.ExitingBlocks.contains(Pred) &&
                              Tainted.contains(Pred->getTerminator())
                          ? OM.lookup(Pred).second
                          : OM.lookup(Pred).first;

        llvm::Instruction *C = new llvm::LoadInst(OutPtr->getAllocatedType(),
                                                  OutPtr, "", InsertionPoint);

        MemInsts.push_back(C);

        // Whenever Bp is a Loop Latch containing the loop condition, we shall
        // not include its predicate in the incoming conditions of BB.
        if (Branch->isConditional() && LW.Latches.find(Pred) == LatchEnd) {
            auto P = Branch->getCondition();
            // If we are at an else branch, then we should negate the
            // predicate. Otherwise, just use the original condition.
            if (Branch->getSuccessor(1) == &BB)
                P = llvm::BinaryOperator::CreateNot(P, "", InsertionPoint);

            C = llvm::BinaryOperator::CreateAnd(C, P, "in.", InsertionPoint);
        }

        In[Pred] = C;
    }

    return {In, MemInsts};
}

std::pair<llvm::StoreInst *, llvm::StoreInst *>
lif::bindOut(llvm::BasicBlock &BB, llvm::Value *OutPtr, llvm::Value *FreezedPtr,
             const Incoming &In, const LoopWrapper &LW) {
    auto InsertionPoint = BB.getTerminator();
    auto BoolTy = llvm::IntegerType::getInt1Ty(BB.getContext());
    auto True = llvm::ConstantInt::getTrue(BoolTy);

    // If there are no incoming conditions, we set the out value as true.
    llvm::Value *OutVal = True;
    if (!In.empty()) OutVal = fold(In, InsertionPoint, LW);

    auto StoreOut = new llvm::StoreInst(OutVal, OutPtr, InsertionPoint);
    llvm::StoreInst *StoreFreezed = nullptr;

    if (FreezedPtr) {
        auto LoadFreezed = new llvm::LoadInst(BoolTy, FreezedPtr,
                                              "load.freezed", InsertionPoint);
        auto OrFreezed = llvm::BinaryOperator::CreateOr(
            LoadFreezed, OutVal, "or.freezed", InsertionPoint);
        StoreFreezed =
            new llvm::StoreInst(OrFreezed, FreezedPtr, InsertionPoint);
    }

    return {StoreOut, StoreFreezed};
}

std::pair<InMap, llvm::SmallVector<llvm::Instruction *, 32>>
lif::bindAll(llvm::Function &F, const OutMap OM, const LoopWrapper &LW,
             const llvm::DenseSet<llvm::Value *> &Tainted) {
    InMap IM(F.size());
    llvm::SmallVector<llvm::Instruction *, 32> MemInsts;

    auto BoolTy = llvm::IntegerType::getInt1Ty(F.getContext());
    auto False = llvm::ConstantInt::getFalse(BoolTy);
    auto LatchEnd = LW.Latches.end();

    for (auto &BB : F) {
        auto [In, MemInstsIn] = bindIn(BB, OM, LW, Tainted);
        IM[&BB] = In;
        MemInsts.insert(MemInsts.end(), MemInstsIn.begin(), MemInstsIn.end());
        auto [OutPtr, FreezedPtr] = OM.lookup(&BB);
        // Whenever BB is a loop latch, we need to initialize its reserved
        // outgoing variable as "false", for it is used to compute the incoming
        // conditions of the loop header. Otherwise, the initial value will be
        // a trash, which can produce undefined behavior.
        if (LW.Latches.find(&BB) != LatchEnd) {
            new llvm::StoreInst(
                False, OutPtr,
                llvm::cast<llvm::Instruction>(OutPtr)->getNextNode());
        }
        auto [StoreOut, StoreFreezed] = bindOut(BB, OutPtr, FreezedPtr, In, LW);
        MemInsts.push_back(StoreOut);
        if (StoreFreezed) MemInsts.push_back(StoreFreezed);
    }

    return {IM, MemInsts};
}

llvm::Value *lif::fold(const Incoming &In, llvm::Instruction *InsertionPoint,
                       const LoopWrapper &LW) {
    auto Or = [InsertionPoint](auto X, auto Y) {
        return llvm::BinaryOperator::CreateOr(X, Y, "cond.fold",
                                              InsertionPoint);
    };

    auto BoolTy = llvm::IntegerType::getInt1Ty(InsertionPoint->getContext());
    llvm::Value *Fold = llvm::ConstantInt::getFalse(BoolTy);

    auto BB = InsertionPoint->getParent();
    if (!LW.Headers.contains(BB)) {
        for (auto [_, Cond] : In) Fold = Or(Fold, Cond);
        return Fold;
    }

    auto L = LW.LI.getLoopFor(BB);
    auto PreHeader = L->getLoopPreheader();
    assert(PreHeader &&
           "error: we require loops to have a preheader! please, run the "
           "--loop-simplify pass.");

    auto Latch = L->getLoopLatch();
    assert(Latch &&
           "error: we require loops to have a unique latch! please, run the "
           "--loop-simplify pass.");

    assert(In.size() == 2 &&
           "error: wrong number of incoming conditions for loop header!");

    auto BackedgeNotTaken = llvm::BinaryOperator::CreateNot(
        LW.BackedgeTakenPhi.lookup(BB), "backedge.nottaken", InsertionPoint);

    auto AndFw =
        llvm::BinaryOperator::CreateAnd(BackedgeNotTaken, In.lookup(PreHeader),
                                        "fwcond.and.btaken", InsertionPoint);

    return Or(AndFw, In.lookup(Latch));
}
