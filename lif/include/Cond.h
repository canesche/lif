//===-- Cond.h --------------------------------------------------*- C++ -*-===//
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
/// This file contains the declaration of types and functions related to
/// incoming and outgoing conditions of a basic block.
///
//===----------------------------------------------------------------------===//

#ifndef LIF_COND_H
#define LIF_COND_H

#include "Loop.h"

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Value.h>

namespace lif {
/// A condition from Bp to B, where Bp is a immediate predecessor of B.
///
/// A condition from path B1 to Bk is a set of expressions (predicates) such as
/// {p1, ..., pk}, i.e. c = p1 & ... & pk. A block can have multiple incoming
/// conditions expressed as a set of sets of preds such as {{p1, ..., pk}, {q1,
/// ..., qn}}, with c1 = p1 & ... & pk and c2 = q1 & ... & qn.
///
/// The outgoing condition of a block is a single value represented by some
/// variable out. Hence, for a set of incoming conditions {{p1, ..., pk}, {q1,
/// ..., qn}}, we have an outgoing condition out = c1 | c2.
///
/// The incoming condition, therefore, is defined as Out(Bp) U {predicate(Bp,
/// B)}, where Out(Bp) is the outgoing condition of Bp.
struct Incoming {
    /// Let Out(Bp) = x and predicate(Bp, B) = p. Then, Cond = x & p.
    llvm::Value *Cond;
    /// The predecessor basic block from where the condition comes.
    llvm::BasicBlock *From;
};

/// A map between a basic block and its incoming conditions.
using InMap =
    llvm::DenseMap<llvm::BasicBlock *, llvm::SmallVector<Incoming, 4>>;

/// A map between a basic block and its outgoing condition.
using OutMap = llvm::DenseMap<llvm::BasicBlock *, llvm::AllocaInst *>;

/// Allocates a variable for each basic block (that is not an exit block) in \p
/// F representing their outgoing conditions.
///
/// The actual computation of the outgoing condition is not done here. This
/// function only reserves a name for the out variable. The size of each basic
/// block in \p F grows by 1 inst.
///
/// \returns a map between basic blocks and their outgoing conditions.
OutMap allocOut(llvm::Function &F);

/// Computes the incoming conditions for a given basic block.
///
/// The size of the basic block grows according to the # of instructions needed
/// to compute the incoming conditions.
///
/// \returns a list of incoming conditions plus a list the Load/Stores created.
std::pair<llvm::SmallVector<Incoming, 4>,
          llvm::SmallVector<llvm::Instruction *, 4>>
bindIn(llvm::BasicBlock &BB, const OutMap OM, const LoopWrapper &LW);

/// Computes the outgoing condition for \p BB.
///
/// The size of the basic block grows according to the # of instructions needed
/// to compute the outgoing condition.
///
/// \returns the Store created to set the value of the outgoing condition.
llvm::StoreInst *bindOut(llvm::BasicBlock &BB, llvm::Value *OutPtr,
                         const llvm::SmallVectorImpl<Incoming> &Incomings);

/// Traverses the basic blocks of \p F, binding the proper incoming and outgoing
/// conditions to them.
///
/// The size of each basic block in \p F grows according to the # of
/// instructions needed to compute both their incoming and outgoing conds.
///
/// \returns a map between basic blocks and their incoming conditions plus a
/// list of the Load/Stores generated.
std::pair<InMap, llvm::SmallVector<llvm::Instruction *, 32>>
bindAll(llvm::Function &F, const OutMap OM, const LoopWrapper &LW);

/// Fold a list of incoming conds. (\p Incomings) into a single value by
/// applying the | (or) operator.
///
/// This method expects the lenght of \p Incomings > 0. Also, for simplicity,
/// if the \p Incomings contains a single incoming cond., the returned value
/// will be Incomings[0] | false.
///
/// \returns a new binary operator representing the folded condition.
llvm::BinaryOperator *fold(const llvm::SmallVectorImpl<Incoming> &Incomings);
} // namespace lif

#endif
