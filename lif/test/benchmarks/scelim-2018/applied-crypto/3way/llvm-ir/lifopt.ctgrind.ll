; ModuleID = 'llvm-ir/lif.ctgrind.ll'
source_filename = "llvm-link"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%i32ptr.wrapped.ty = type { i32*, i64 }
%struct.twy_ctx = type { [3 x i32], [3 x i32], [12 x i32], [12 x i32] }

@.str = private unnamed_addr constant [7 x i8] c"secret\00", section "llvm.metadata"
@.str.1 = private unnamed_addr constant [11 x i8] c"src/main.c\00", section "llvm.metadata"

; Function Attrs: nofree noinline norecurse nosync nounwind sspstrong uwtable
define dso_local void @mu(%i32ptr.wrapped.ty* nocapture noundef readonly %a) local_unnamed_addr #0 {
entry:
  %0 = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a, i64 0, i32 0
  %a.unwrapped = load i32*, i32** %0, align 8
  %arrayidx10 = getelementptr inbounds i32, i32* %a.unwrapped, i64 1
  %arrayidx17 = getelementptr inbounds i32, i32* %a.unwrapped, i64 2
  %a.unwrapped.promoted = load i32, i32* %a.unwrapped, align 4
  %arrayidx10.promoted = load i32, i32* %arrayidx10, align 4
  %arrayidx17.promoted = load i32, i32* %arrayidx17, align 4
  br label %for.body

for.body:                                         ; preds = %entry, %for.body
  %i.0.rewritten20 = phi i32 [ 0, %entry ], [ %inc, %for.body ]
  %b.sroa.0.019 = phi i32 [ 0, %entry ], [ %select.val.46, %for.body ]
  %b.sroa.6.018 = phi i32 [ 0, %entry ], [ %select.val.39, %for.body ]
  %b.sroa.12.017 = phi i32 [ 0, %entry ], [ %select.val., %for.body ]
  %shr1116 = phi i32 [ %a.unwrapped.promoted, %entry ], [ %shr, %for.body ]
  %shr261215 = phi i32 [ %arrayidx10.promoted, %entry ], [ %shr26, %for.body ]
  %shr281314 = phi i32 [ %arrayidx17.promoted, %entry ], [ %shr28, %for.body ]
  %shl = shl i32 %b.sroa.0.019, 1
  %shl5 = shl i32 %b.sroa.6.018, 1
  %shl7 = shl i32 %b.sroa.12.017, 1
  %and = and i32 %shr1116, 1
  %select.val. = or i32 %and, %shl7
  %and11 = and i32 %shr261215, 1
  %select.val.39 = or i32 %and11, %shl5
  %and18 = and i32 %shr281314, 1
  %select.val.46 = or i32 %and18, %shl
  %shr = ashr i32 %shr1116, 1
  %shr26 = ashr i32 %shr261215, 1
  %shr28 = ashr i32 %shr281314, 1
  %inc = add nuw nsw i32 %i.0.rewritten20, 1
  %exitcond.not = icmp eq i32 %inc, 32
  br i1 %exitcond.not, label %for.end, label %for.body, !llvm.loop !6

for.end:                                          ; preds = %for.body
  store i32 %select.val.46, i32* %a.unwrapped, align 4
  store i32 %select.val.39, i32* %arrayidx10, align 4
  store i32 %select.val., i32* %arrayidx17, align 4
  ret void
}

; Function Attrs: mustprogress nofree noinline norecurse nosync nounwind sspstrong uwtable willreturn
define dso_local void @gamma(%i32ptr.wrapped.ty* nocapture noundef readonly %a) local_unnamed_addr #1 {
entry:
  %0 = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a, i64 0, i32 0
  %a.unwrapped = load i32*, i32** %0, align 8
  %1 = load i32, i32* %a.unwrapped, align 4
  %arrayidx1 = getelementptr inbounds i32, i32* %a.unwrapped, i64 1
  %2 = load i32, i32* %arrayidx1, align 4
  %arrayidx2 = getelementptr inbounds i32, i32* %a.unwrapped, i64 2
  %3 = load i32, i32* %arrayidx2, align 4
  %neg = xor i32 %3, -1
  %or = or i32 %2, %neg
  %xor = xor i32 %or, %1
  %neg7 = xor i32 %1, -1
  %or8 = or i32 %3, %neg7
  %xor9 = xor i32 %or8, %2
  %neg14 = xor i32 %2, -1
  %or15 = or i32 %1, %neg14
  %xor16 = xor i32 %3, %or15
  store i32 %xor, i32* %a.unwrapped, align 4
  store i32 %xor9, i32* %arrayidx1, align 4
  store i32 %xor16, i32* %arrayidx2, align 4
  ret void
}

; Function Attrs: mustprogress nofree noinline norecurse nosync nounwind sspstrong uwtable willreturn
define dso_local void @theta(%i32ptr.wrapped.ty* nocapture noundef readonly %a) local_unnamed_addr #1 {
entry:
  %0 = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a, i64 0, i32 0
  %a.unwrapped = load i32*, i32** %0, align 8
  %1 = load i32, i32* %a.unwrapped, align 4
  %shr = ashr i32 %1, 16
  %xor = xor i32 %shr, %1
  %arrayidx2 = getelementptr inbounds i32, i32* %a.unwrapped, i64 1
  %2 = load i32, i32* %arrayidx2, align 4
  %shl = shl i32 %2, 16
  %shr5 = ashr i32 %2, 16
  %arrayidx7 = getelementptr inbounds i32, i32* %a.unwrapped, i64 2
  %3 = load i32, i32* %arrayidx7, align 4
  %shl8 = shl i32 %3, 16
  %shr11 = ashr i32 %2, 24
  %shl14 = shl i32 %3, 8
  %shr17 = ashr i32 %3, 8
  %shl20 = shl i32 %1, 24
  %shr23 = ashr i32 %3, 16
  %shl26 = shl i32 %1, 16
  %shr29 = ashr i32 %3, 24
  %shl32 = shl i32 %1, 8
  %xor3 = xor i32 %xor, %shl20
  %xor6 = xor i32 %xor3, %shl26
  %xor9 = xor i32 %xor6, %shl32
  %xor12 = xor i32 %xor9, %shl
  %xor15 = xor i32 %xor12, %shr5
  %xor18 = xor i32 %xor15, %shr11
  %xor21 = xor i32 %xor18, %shl8
  %xor24 = xor i32 %xor21, %shl14
  %xor27 = xor i32 %xor24, %shr17
  %xor30 = xor i32 %xor27, %shr23
  %xor33 = xor i32 %xor30, %shr29
  %shr55 = ashr i32 %1, 8
  %shl58 = shl i32 %2, 24
  %shr67 = ashr i32 %1, 24
  %shl70 = shl i32 %2, 8
  %xor38 = xor i32 %shl26, %2
  %xor41 = xor i32 %xor38, %shl32
  %xor44 = xor i32 %xor41, %shr55
  %xor47 = xor i32 %xor44, %shr
  %xor50 = xor i32 %xor47, %shr67
  %xor53 = xor i32 %xor50, %shr5
  %xor56 = xor i32 %xor53, %shl58
  %xor59 = xor i32 %xor56, %shl
  %xor62 = xor i32 %xor59, %shl70
  %xor65 = xor i32 %xor62, %shl8
  %xor68 = xor i32 %xor65, %shr23
  %xor71 = xor i32 %xor68, %shr29
  %shr93 = ashr i32 %2, 8
  %shl96 = shl i32 %3, 24
  %xor76 = xor i32 %shr, %shl26
  %xor79 = xor i32 %xor76, %shr67
  %xor82 = xor i32 %xor79, %3
  %xor85 = xor i32 %xor82, %shl
  %xor88 = xor i32 %xor85, %shl70
  %xor91 = xor i32 %xor88, %shr93
  %xor94 = xor i32 %xor91, %shr5
  %xor97 = xor i32 %xor94, %shr11
  %xor100 = xor i32 %xor97, %shr23
  %xor103 = xor i32 %xor100, %shl96
  %xor106 = xor i32 %xor103, %shl8
  %xor109 = xor i32 %xor106, %shl14
  store i32 %xor33, i32* %a.unwrapped, align 4
  store i32 %xor71, i32* %arrayidx2, align 4
  store i32 %xor109, i32* %arrayidx7, align 4
  ret void
}

; Function Attrs: mustprogress nofree noinline norecurse nosync nounwind sspstrong uwtable willreturn
define dso_local void @pi_1(%i32ptr.wrapped.ty* nocapture noundef readonly %a) local_unnamed_addr #1 {
entry:
  %0 = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a, i64 0, i32 0
  %a.unwrapped = load i32*, i32** %0, align 8
  %1 = load i32, i32* %a.unwrapped, align 4
  %shr = ashr i32 %1, 10
  %shl = shl i32 %1, 22
  %xor = xor i32 %shr, %shl
  store i32 %xor, i32* %a.unwrapped, align 4
  %arrayidx3 = getelementptr inbounds i32, i32* %a.unwrapped, i64 2
  %2 = load i32, i32* %arrayidx3, align 4
  %shl4 = shl i32 %2, 1
  %shr6 = ashr i32 %2, 31
  %xor7 = xor i32 %shl4, %shr6
  store i32 %xor7, i32* %arrayidx3, align 4
  ret void
}

; Function Attrs: mustprogress nofree noinline norecurse nosync nounwind sspstrong uwtable willreturn
define dso_local void @pi_2(%i32ptr.wrapped.ty* nocapture noundef readonly %a) local_unnamed_addr #1 {
entry:
  %0 = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a, i64 0, i32 0
  %a.unwrapped = load i32*, i32** %0, align 8
  %1 = load i32, i32* %a.unwrapped, align 4
  %shl = shl i32 %1, 1
  %shr = ashr i32 %1, 31
  %xor = xor i32 %shl, %shr
  store i32 %xor, i32* %a.unwrapped, align 4
  %arrayidx3 = getelementptr inbounds i32, i32* %a.unwrapped, i64 2
  %2 = load i32, i32* %arrayidx3, align 4
  %shr4 = ashr i32 %2, 10
  %shl6 = shl i32 %2, 22
  %xor7 = xor i32 %shr4, %shl6
  store i32 %xor7, i32* %arrayidx3, align 4
  ret void
}

; Function Attrs: mustprogress nofree noinline norecurse nosync nounwind sspstrong uwtable willreturn
define dso_local void @rho(%i32ptr.wrapped.ty* nocapture noundef readonly %a) local_unnamed_addr #1 {
entry:
  %a.field0.length.ptr = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a, i64 0, i32 1
  %a.field0.length = load i64, i64* %a.field0.length.ptr, align 8
  %a.unwrapped.wrapped5 = alloca %i32ptr.wrapped.ty, align 8
  %a.unwrapped.wrapped3 = alloca %i32ptr.wrapped.ty, align 8
  %a.unwrapped.wrapped1 = alloca %i32ptr.wrapped.ty, align 8
  %a.unwrapped.wrapped = alloca %i32ptr.wrapped.ty, align 8
  %0 = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a, i64 0, i32 0
  %a.unwrapped = load i32*, i32** %0, align 8
  %a.unwrapped.unwrapped4 = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a.unwrapped.wrapped3, i64 0, i32 0
  %a.unwrapped.wrapped3.field0.length.ptr = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a.unwrapped.wrapped3, i64 0, i32 1
  store i64 %a.field0.length, i64* %a.unwrapped.wrapped3.field0.length.ptr, align 8
  store i32* %a.unwrapped, i32** %a.unwrapped.unwrapped4, align 8
  call void @theta(%i32ptr.wrapped.ty* nonnull %a.unwrapped.wrapped3)
  %a.unwrapped.unwrapped2 = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a.unwrapped.wrapped1, i64 0, i32 0
  %a.unwrapped.wrapped1.field0.length.ptr = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a.unwrapped.wrapped1, i64 0, i32 1
  store i64 %a.field0.length, i64* %a.unwrapped.wrapped1.field0.length.ptr, align 8
  store i32* %a.unwrapped, i32** %a.unwrapped.unwrapped2, align 8
  call void @pi_1(%i32ptr.wrapped.ty* nonnull %a.unwrapped.wrapped1)
  %a.unwrapped.unwrapped6 = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a.unwrapped.wrapped5, i64 0, i32 0
  %a.unwrapped.wrapped5.field0.length.ptr = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a.unwrapped.wrapped5, i64 0, i32 1
  store i64 %a.field0.length, i64* %a.unwrapped.wrapped5.field0.length.ptr, align 8
  store i32* %a.unwrapped, i32** %a.unwrapped.unwrapped6, align 8
  call void @gamma(%i32ptr.wrapped.ty* nonnull %a.unwrapped.wrapped5)
  %a.unwrapped.unwrapped = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a.unwrapped.wrapped, i64 0, i32 0
  %a.unwrapped.wrapped.field0.length.ptr = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a.unwrapped.wrapped, i64 0, i32 1
  store i64 %a.field0.length, i64* %a.unwrapped.wrapped.field0.length.ptr, align 8
  store i32* %a.unwrapped, i32** %a.unwrapped.unwrapped, align 8
  call void @pi_2(%i32ptr.wrapped.ty* nonnull %a.unwrapped.wrapped)
  ret void
}

; Function Attrs: nofree noinline norecurse nosync nounwind sspstrong uwtable
define dso_local void @rndcon_gen(i32 noundef %strt, %i32ptr.wrapped.ty* nocapture noundef readonly %rtab) local_unnamed_addr #0 {
entry:
  %0 = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %rtab, i64 0, i32 0
  %rtab.unwrapped = load i32*, i32** %0, align 8
  br label %for.body

for.body:                                         ; preds = %entry, %for.body
  %indvars.iv = phi i64 [ 0, %entry ], [ %indvars.iv.next, %for.body ]
  %strt.addr.0.rewritten6 = phi i32 [ %strt, %entry ], [ %spec.select3, %for.body ]
  %arrayidx = getelementptr inbounds i32, i32* %rtab.unwrapped, i64 %indvars.iv
  store i32 %strt.addr.0.rewritten6, i32* %arrayidx, align 4
  %shl = shl i32 %strt.addr.0.rewritten6, 1
  %1 = and i32 %strt.addr.0.rewritten6, 32768
  %tobool.not = icmp eq i32 %1, 0
  %xor = xor i32 %shl, 69649
  %spec.select3 = select i1 %tobool.not, i32 %shl, i32 %xor
  %indvars.iv.next = add nuw nsw i64 %indvars.iv, 1
  %exitcond.not = icmp eq i64 %indvars.iv.next, 12
  br i1 %exitcond.not, label %for.end, label %for.body, !llvm.loop !8

for.end:                                          ; preds = %for.body
  ret void
}

; Function Attrs: nofree noinline norecurse nosync nounwind sspstrong uwtable
define dso_local void @encrypt(%struct.twy_ctx* nocapture noundef readonly %c, %i32ptr.wrapped.ty* nocapture noundef readonly %a) local_unnamed_addr #0 {
entry:
  %a.field0.length.ptr = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a, i64 0, i32 1
  %a.field0.length = load i64, i64* %a.field0.length.ptr, align 8
  %a.unwrapped.wrapped9 = alloca %i32ptr.wrapped.ty, align 8
  %a.unwrapped.wrapped = alloca %i32ptr.wrapped.ty, align 8
  %0 = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a, i64 0, i32 0
  %a.unwrapped = load i32*, i32** %0, align 8
  %arrayidx = getelementptr inbounds %struct.twy_ctx, %struct.twy_ctx* %c, i64 0, i32 0, i64 0
  %arrayidx5 = getelementptr inbounds %struct.twy_ctx, %struct.twy_ctx* %c, i64 0, i32 0, i64 1
  %arrayidx6 = getelementptr inbounds i32, i32* %a.unwrapped, i64 1
  %arrayidx9 = getelementptr inbounds %struct.twy_ctx, %struct.twy_ctx* %c, i64 0, i32 0, i64 2
  %arrayidx14 = getelementptr inbounds i32, i32* %a.unwrapped, i64 2
  %a.unwrapped.unwrapped = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a.unwrapped.wrapped, i64 0, i32 0
  %a.unwrapped.wrapped.field0.length.ptr = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a.unwrapped.wrapped, i64 0, i32 1
  br label %for.body

for.body:                                         ; preds = %entry, %for.body
  %indvars.iv = phi i64 [ 0, %entry ], [ %indvars.iv.next, %for.body ]
  %1 = load i32, i32* %arrayidx, align 4
  %arrayidx1 = getelementptr inbounds %struct.twy_ctx, %struct.twy_ctx* %c, i64 0, i32 2, i64 %indvars.iv
  %2 = load i32, i32* %arrayidx1, align 4
  %shl = shl i32 %2, 16
  %xor = xor i32 %shl, %1
  %3 = load i32, i32* %a.unwrapped, align 4
  %xor3 = xor i32 %xor, %3
  store i32 %xor3, i32* %a.unwrapped, align 4
  %4 = load i32, i32* %arrayidx5, align 4
  %5 = load i32, i32* %arrayidx6, align 4
  %xor7 = xor i32 %5, %4
  store i32 %xor7, i32* %arrayidx6, align 4
  %6 = load i32, i32* %arrayidx9, align 4
  %7 = load i32, i32* %arrayidx1, align 4
  %xor13 = xor i32 %7, %6
  %8 = load i32, i32* %arrayidx14, align 4
  %xor15 = xor i32 %xor13, %8
  store i32 %xor15, i32* %arrayidx14, align 4
  store i64 %a.field0.length, i64* %a.unwrapped.wrapped.field0.length.ptr, align 8
  store i32* %a.unwrapped, i32** %a.unwrapped.unwrapped, align 8
  call void @rho(%i32ptr.wrapped.ty* nonnull %a.unwrapped.wrapped)
  %indvars.iv.next = add nuw nsw i64 %indvars.iv, 1
  %exitcond.not = icmp eq i64 %indvars.iv.next, 11
  br i1 %exitcond.not, label %for.end, label %for.body, !llvm.loop !9

for.end:                                          ; preds = %for.body
  %9 = load i32, i32* %arrayidx, align 4
  %arrayidx19 = getelementptr inbounds %struct.twy_ctx, %struct.twy_ctx* %c, i64 0, i32 2, i64 11
  %10 = load i32, i32* %arrayidx19, align 4
  %shl20 = shl i32 %10, 16
  %xor21 = xor i32 %shl20, %9
  %11 = load i32, i32* %a.unwrapped, align 4
  %xor23 = xor i32 %xor21, %11
  store i32 %xor23, i32* %a.unwrapped, align 4
  %12 = load i32, i32* %arrayidx5, align 4
  %13 = load i32, i32* %arrayidx6, align 4
  %xor27 = xor i32 %13, %12
  store i32 %xor27, i32* %arrayidx6, align 4
  %14 = load i32, i32* %arrayidx9, align 4
  %15 = load i32, i32* %arrayidx19, align 4
  %xor32 = xor i32 %15, %14
  %16 = load i32, i32* %arrayidx14, align 4
  %xor34 = xor i32 %xor32, %16
  store i32 %xor34, i32* %arrayidx14, align 4
  %a.unwrapped.unwrapped10 = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a.unwrapped.wrapped9, i64 0, i32 0
  %a.unwrapped.wrapped9.field0.length.ptr = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %a.unwrapped.wrapped9, i64 0, i32 1
  store i64 %a.field0.length, i64* %a.unwrapped.wrapped9.field0.length.ptr, align 8
  store i32* %a.unwrapped, i32** %a.unwrapped.unwrapped10, align 8
  call void @theta(%i32ptr.wrapped.ty* nonnull %a.unwrapped.wrapped9)
  ret void
}

; Function Attrs: nofree noinline norecurse nosync nounwind sspstrong uwtable
define dso_local void @twy_key(%i32ptr.wrapped.ty* nocapture noundef readonly %key, %struct.twy_ctx* noundef %c) local_unnamed_addr #0 {
entry:
  %arraydecay15.wrapped = alloca %i32ptr.wrapped.ty, align 8
  %arraydecay.wrapped = alloca %i32ptr.wrapped.ty, align 8
  %arraydecay16.wrapped = alloca %i32ptr.wrapped.ty, align 8
  %arraydecay17.wrapped = alloca %i32ptr.wrapped.ty, align 8
  %0 = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %key, i64 0, i32 0
  %key.unwrapped = load i32*, i32** %0, align 8
  %1 = load i32, i32* %key.unwrapped, align 4
  %arrayidx1 = getelementptr inbounds %struct.twy_ctx, %struct.twy_ctx* %c, i64 0, i32 0, i64 0
  store i32 %1, i32* %arrayidx1, align 4
  %arrayidx2 = getelementptr inbounds %struct.twy_ctx, %struct.twy_ctx* %c, i64 0, i32 1, i64 0
  store i32 %1, i32* %arrayidx2, align 4
  %arrayidx3 = getelementptr inbounds i32, i32* %key.unwrapped, i64 1
  %2 = load i32, i32* %arrayidx3, align 4
  %arrayidx5 = getelementptr inbounds %struct.twy_ctx, %struct.twy_ctx* %c, i64 0, i32 0, i64 1
  store i32 %2, i32* %arrayidx5, align 4
  %arrayidx7 = getelementptr inbounds %struct.twy_ctx, %struct.twy_ctx* %c, i64 0, i32 1, i64 1
  store i32 %2, i32* %arrayidx7, align 4
  %arrayidx8 = getelementptr inbounds i32, i32* %key.unwrapped, i64 2
  %3 = load i32, i32* %arrayidx8, align 4
  %arrayidx10 = getelementptr inbounds %struct.twy_ctx, %struct.twy_ctx* %c, i64 0, i32 0, i64 2
  store i32 %3, i32* %arrayidx10, align 4
  %arrayidx12 = getelementptr inbounds %struct.twy_ctx, %struct.twy_ctx* %c, i64 0, i32 1, i64 2
  store i32 %3, i32* %arrayidx12, align 4
  %arraydecay.unwrapped = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %arraydecay.wrapped, i64 0, i32 0
  %arraydecay.wrapped.field0.length.ptr = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %arraydecay.wrapped, i64 0, i32 1
  store i64 3, i64* %arraydecay.wrapped.field0.length.ptr, align 8
  store i32* %arrayidx2, i32** %arraydecay.unwrapped, align 8
  call void @theta(%i32ptr.wrapped.ty* nonnull %arraydecay.wrapped)
  %arraydecay15.unwrapped = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %arraydecay15.wrapped, i64 0, i32 0
  %arraydecay15.wrapped.field0.length.ptr = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %arraydecay15.wrapped, i64 0, i32 1
  store i64 3, i64* %arraydecay15.wrapped.field0.length.ptr, align 8
  store i32* %arrayidx2, i32** %arraydecay15.unwrapped, align 8
  call void @mu(%i32ptr.wrapped.ty* nonnull %arraydecay15.wrapped)
  %arraydecay16 = getelementptr inbounds %struct.twy_ctx, %struct.twy_ctx* %c, i64 0, i32 2, i64 0
  %arraydecay16.unwrapped = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %arraydecay16.wrapped, i64 0, i32 0
  %arraydecay16.wrapped.field0.length.ptr = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %arraydecay16.wrapped, i64 0, i32 1
  store i64 12, i64* %arraydecay16.wrapped.field0.length.ptr, align 8
  store i32* %arraydecay16, i32** %arraydecay16.unwrapped, align 8
  call void @rndcon_gen(i32 2827, %i32ptr.wrapped.ty* nonnull %arraydecay16.wrapped)
  %arraydecay17 = getelementptr inbounds %struct.twy_ctx, %struct.twy_ctx* %c, i64 0, i32 3, i64 0
  %arraydecay17.unwrapped = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %arraydecay17.wrapped, i64 0, i32 0
  %arraydecay17.wrapped.field0.length.ptr = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %arraydecay17.wrapped, i64 0, i32 1
  store i64 12, i64* %arraydecay17.wrapped.field0.length.ptr, align 8
  store i32* %arraydecay17, i32** %arraydecay17.unwrapped, align 8
  call void @rndcon_gen(i32 45489, %i32ptr.wrapped.ty* nonnull %arraydecay17.wrapped)
  ret void
}

; Function Attrs: noinline nounwind sspstrong uwtable
define dso_local i32 @main() local_unnamed_addr #2 {
entry:
  %arraydecay23.wrapped = alloca %i32ptr.wrapped.ty, align 8
  %arraydecay24.wrapped = alloca %i32ptr.wrapped.ty, align 8
  %gc = alloca %struct.twy_ctx, align 4
  %in_key = alloca [3 x i32], align 4
  %in = alloca [3 x i32], align 4
  %_zzq_args = alloca [6 x i64], align 16
  %_zzq_result = alloca i64, align 8
  %_zzq_args12 = alloca [6 x i64], align 16
  %_zzq_result13 = alloca i64, align 8
  %in_key1 = bitcast [3 x i32]* %in_key to i8*
  call void @llvm.var.annotation(i8* nonnull %in_key1, i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str, i64 0, i64 0), i8* getelementptr inbounds ([11 x i8], [11 x i8]* @.str.1, i64 0, i64 0), i32 54, i8* null)
  %in2 = bitcast [3 x i32]* %in to i8*
  call void @llvm.var.annotation(i8* nonnull %in2, i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str, i64 0, i64 0), i8* getelementptr inbounds ([11 x i8], [11 x i8]* @.str.1, i64 0, i64 0), i32 55, i8* null)
  %arraydecay = getelementptr inbounds [3 x i32], [3 x i32]* %in_key, i64 0, i64 0
  %call = call i64 @read(i32 noundef 0, i8* noundef nonnull %in_key1, i64 noundef 12) #5
  %arraydecay3 = getelementptr inbounds [3 x i32], [3 x i32]* %in, i64 0, i64 0
  %call4 = call i64 @read(i32 noundef 0, i8* noundef nonnull %in2, i64 noundef 12) #5
  %arrayidx = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args, i64 0, i64 0
  store volatile i64 1296236545, i64* %arrayidx, align 16
  %0 = ptrtoint [3 x i32]* %in_key to i64
  %arrayidx6 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args, i64 0, i64 1
  store volatile i64 %0, i64* %arrayidx6, align 8
  %arrayidx7 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args, i64 0, i64 2
  store volatile i64 3, i64* %arrayidx7, align 16
  %arrayidx8 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args, i64 0, i64 3
  store volatile i64 0, i64* %arrayidx8, align 8
  %arrayidx9 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args, i64 0, i64 4
  store volatile i64 0, i64* %arrayidx9, align 16
  %arrayidx10 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args, i64 0, i64 5
  store volatile i64 0, i64* %arrayidx10, align 8
  %1 = call i64 asm sideeffect "rolq $$3,  %rdi ; rolq $$13, %rdi\0A\09rolq $$61, %rdi ; rolq $$51, %rdi\0A\09xchgq %rbx,%rbx", "={dx},{ax},0,~{cc},~{memory},~{dirflag},~{fpsr},~{flags}"(i64* nonnull %arrayidx, i64 0) #5, !srcloc !10
  store volatile i64 %1, i64* %_zzq_result, align 8
  %_zzq_result.0._zzq_result.0._zzq_result.0. = load volatile i64, i64* %_zzq_result, align 8
  %arrayidx14 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args12, i64 0, i64 0
  store volatile i64 1296236545, i64* %arrayidx14, align 16
  %2 = ptrtoint [3 x i32]* %in to i64
  %arrayidx16 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args12, i64 0, i64 1
  store volatile i64 %2, i64* %arrayidx16, align 8
  %arrayidx17 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args12, i64 0, i64 2
  store volatile i64 3, i64* %arrayidx17, align 16
  %arrayidx18 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args12, i64 0, i64 3
  store volatile i64 0, i64* %arrayidx18, align 8
  %arrayidx19 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args12, i64 0, i64 4
  store volatile i64 0, i64* %arrayidx19, align 16
  %arrayidx20 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args12, i64 0, i64 5
  store volatile i64 0, i64* %arrayidx20, align 8
  %3 = call i64 asm sideeffect "rolq $$3,  %rdi ; rolq $$13, %rdi\0A\09rolq $$61, %rdi ; rolq $$51, %rdi\0A\09xchgq %rbx,%rbx", "={dx},{ax},0,~{cc},~{memory},~{dirflag},~{fpsr},~{flags}"(i64* nonnull %arrayidx14, i64 0) #5, !srcloc !11
  store volatile i64 %3, i64* %_zzq_result13, align 8
  %_zzq_result13.0._zzq_result13.0._zzq_result13.0. = load volatile i64, i64* %_zzq_result13, align 8
  %arraydecay23.unwrapped = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %arraydecay23.wrapped, i64 0, i32 0
  %arraydecay23.wrapped.field0.length.ptr = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %arraydecay23.wrapped, i64 0, i32 1
  store i64 3, i64* %arraydecay23.wrapped.field0.length.ptr, align 8
  store i32* %arraydecay, i32** %arraydecay23.unwrapped, align 8
  call void @twy_key(%i32ptr.wrapped.ty* nonnull %arraydecay23.wrapped, %struct.twy_ctx* nonnull %gc)
  %arraydecay24.unwrapped = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %arraydecay24.wrapped, i64 0, i32 0
  %arraydecay24.wrapped.field0.length.ptr = getelementptr inbounds %i32ptr.wrapped.ty, %i32ptr.wrapped.ty* %arraydecay24.wrapped, i64 0, i32 1
  store i64 3, i64* %arraydecay24.wrapped.field0.length.ptr, align 8
  store i32* %arraydecay3, i32** %arraydecay24.unwrapped, align 8
  call void @encrypt(%struct.twy_ctx* nonnull %gc, %i32ptr.wrapped.ty* nonnull %arraydecay24.wrapped)
  %call26 = call i64 @write(i32 noundef 1, i8* noundef nonnull %in2, i64 noundef 12) #5
  ret i32 0
}

; Function Attrs: inaccessiblememonly mustprogress nofree nosync nounwind willreturn
declare void @llvm.var.annotation(i8*, i8*, i8*, i32, i8*) #3

; Function Attrs: nofree
declare noundef i64 @read(i32 noundef, i8* nocapture noundef, i64 noundef) local_unnamed_addr #4

; Function Attrs: nofree
declare noundef i64 @write(i32 noundef, i8* nocapture noundef readonly, i64 noundef) local_unnamed_addr #4

attributes #0 = { nofree noinline norecurse nosync nounwind sspstrong uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { mustprogress nofree noinline norecurse nosync nounwind sspstrong uwtable willreturn "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { noinline nounwind sspstrong uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { inaccessiblememonly mustprogress nofree nosync nounwind willreturn }
attributes #4 = { nofree "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #5 = { nounwind }

!llvm.ident = !{!0, !0}
!llvm.module.flags = !{!1, !2, !3, !4, !5}

!0 = !{!"clang version 14.0.6"}
!1 = !{i32 1, !"wchar_size", i32 4}
!2 = !{i32 7, !"PIC Level", i32 2}
!3 = !{i32 7, !"PIE Level", i32 2}
!4 = !{i32 7, !"uwtable", i32 1}
!5 = !{i32 7, !"frame-pointer", i32 2}
!6 = distinct !{!6, !7}
!7 = !{!"llvm.loop.mustprogress"}
!8 = distinct !{!8, !7}
!9 = distinct !{!9, !7}
!10 = !{i64 2148230653, i64 2148230689, i64 2148230757}
!11 = !{i64 2148232213, i64 2148232249, i64 2148232317}
