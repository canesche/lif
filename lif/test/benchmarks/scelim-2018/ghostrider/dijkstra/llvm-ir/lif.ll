; ModuleID = 'llvm-ir/base.ll'
source_filename = "llvm-link"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%"[16 x i32]ptr.wrapped.ty" = type { [16 x i32]*, i64 }

@.str = private unnamed_addr constant [7 x i8] c"secret\00", section "llvm.metadata"
@.str.1 = private unnamed_addr constant [15 x i8] c"lib/dijkstra.c\00", section "llvm.metadata"
@llvm.global.annotations = appending global [1 x { i8*, i8*, i8*, i32, i8* }] [{ i8*, i8*, i8*, i32, i8* } { i8* bitcast (i32* @x to i8*), i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str.3, i32 0, i32 0), i8* getelementptr inbounds ([11 x i8], [11 x i8]* @.str.1.4, i32 0, i32 0), i32 16, i8* null }], section "llvm.metadata"
@x = dso_local global i32 0, align 4
@.str.3 = private unnamed_addr constant [7 x i8] c"secret\00", section "llvm.metadata"
@.str.1.4 = private unnamed_addr constant [11 x i8] c"src/main.c\00", section "llvm.metadata"

; Function Attrs: noinline nounwind sspstrong uwtable
define dso_local i32 @dijkstra(i32 noundef %n, i32 noundef %s, i32 noundef %t, %"[16 x i32]ptr.wrapped.ty"* noundef %e) #0 {
entry:
  %e.field0.length.ptr = getelementptr inbounds %"[16 x i32]ptr.wrapped.ty", %"[16 x i32]ptr.wrapped.ty"* %e, i32 0, i32 1
  %e.field0.length = load i64, i64* %e.field0.length.ptr, align 8
  %pred.alloca68 = alloca i1, align 1
  store i1 true, i1* %pred.alloca68, align 1
  %pred.alloca50 = alloca i1, align 1
  store i1 true, i1* %pred.alloca50, align 1
  %pred.alloca = alloca i1, align 1
  store i1 false, i1* %pred.alloca, align 1
  %out. = alloca i1, align 1
  store i1 false, i1* %out., align 1
  %out.7 = alloca i1, align 1
  store i1 false, i1* %out.7, align 1
  %out.8 = alloca i1, align 1
  store i1 false, i1* %out.8, align 1
  %out.9 = alloca i1, align 1
  store i1 false, i1* %out.9, align 1
  %out.10 = alloca i1, align 1
  store i1 false, i1* %out.10, align 1
  %out.11 = alloca i1, align 1
  store i1 false, i1* %out.11, align 1
  %out.12 = alloca i1, align 1
  store i1 false, i1* %out.12, align 1
  %out.13 = alloca i1, align 1
  store i1 false, i1* %out.13, align 1
  %out.14 = alloca i1, align 1
  store i1 false, i1* %out.14, align 1
  %out.15 = alloca i1, align 1
  store i1 false, i1* %out.15, align 1
  %out.16 = alloca i1, align 1
  store i1 false, i1* %out.16, align 1
  %out.17 = alloca i1, align 1
  store i1 false, i1* %out.17, align 1
  %out.18 = alloca i1, align 1
  store i1 false, i1* %out.18, align 1
  %out.19 = alloca i1, align 1
  store i1 false, i1* %out.19, align 1
  %out.20 = alloca i1, align 1
  store i1 false, i1* %out.20, align 1
  %out.21 = alloca i1, align 1
  store i1 false, i1* %out.21, align 1
  %out.22 = alloca i1, align 1
  store i1 false, i1* %out.22, align 1
  %out.23 = alloca i1, align 1
  store i1 false, i1* %out.23, align 1
  %out.24 = alloca i1, align 1
  store i1 false, i1* %out.24, align 1
  %out.25 = alloca i1, align 1
  store i1 false, i1* %out.25, align 1
  %out.26 = alloca i1, align 1
  store i1 false, i1* %out.26, align 1
  %out.27 = alloca i1, align 1
  store i1 false, i1* %out.27, align 1
  %out.28 = alloca i1, align 1
  store i1 false, i1* %out.28, align 1
  %out.29 = alloca i1, align 1
  store i1 false, i1* %out.29, align 1
  store i1 true, i1* %out., align 1
  store i1 false, i1* %out.9, align 1
  store i1 false, i1* %out.19, align 1
  store i1 false, i1* %out.26, align 1
  store i1 false, i1* %out.28, align 1
  %0 = getelementptr inbounds %"[16 x i32]ptr.wrapped.ty", %"[16 x i32]ptr.wrapped.ty"* %e, i32 0, i32 0
  %e.unwrapped = load [16 x i32]*, [16 x i32]** %0, align 8
  %vis = alloca [16 x i32], align 16
  %dis = alloca [16 x i32], align 16
  %vis1 = bitcast [16 x i32]* %vis to i8*
  call void @llvm.var.annotation(i8* %vis1, i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str, i32 0, i32 0), i8* getelementptr inbounds ([15 x i8], [15 x i8]* @.str.1, i32 0, i32 0), i32 10, i8* null)
  %1 = bitcast [16 x i32]* %vis to i8*
  call void @llvm.memset.p0i8.i64(i8* align 16 %1, i8 0, i64 64, i1 false)
  %dis2 = bitcast [16 x i32]* %dis to i8*
  call void @llvm.var.annotation(i8* %dis2, i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str, i32 0, i32 0), i8* getelementptr inbounds ([15 x i8], [15 x i8]* @.str.1, i32 0, i32 0), i32 11, i8* null)
  %2 = bitcast [16 x i32]* %dis to i8*
  call void @llvm.memset.p0i8.i64(i8* align 16 %2, i8 0, i64 64, i1 false)
  %idxprom = sext i32 %s to i64
  %arrayidx = getelementptr inbounds [16 x i32], [16 x i32]* %vis, i64 0, i64 %idxprom
  store i32 1, i32* %arrayidx, align 4
  %shadow = alloca i64, align 8
  store i64 0, i64* %shadow, align 8
  br label %for.cond

for.cond:                                         ; preds = %for.inc, %entry
  %i.0.rewritten = phi i32 [ 0, %entry ], [ %inc, %for.inc ]
  %fwedge.taken.rewritten = phi i1 [ true, %entry ], [ false, %for.inc ]
  %exitpred.frozen.rewritten = phi i1 [ %cmp, %for.inc ], [ false, %entry ]
  %3 = load i1, i1* %out.9, align 1
  %4 = load i1, i1* %out., align 1
  %fwcond.and.fwtaken = and i1 %fwedge.taken.rewritten, %4
  %cond.fold = or i1 %fwcond.and.fwtaken, %3
  store i1 %cond.fold, i1* %out.7, align 1
  %cmp = icmp slt i32 %i.0.rewritten, %n
  br i1 %cmp, label %for.body, label %for.end

for.body:                                         ; preds = %for.cond
  %5 = load i1, i1* %out.7, align 1
  %in. = and i1 %5, %cmp
  %cond.fold30 = or i1 false, %in.
  store i1 %cond.fold30, i1* %out.8, align 1
  %idxprom3 = sext i32 %s to i64
  %arrayidx4 = getelementptr inbounds [16 x i32], [16 x i32]* %e.unwrapped, i64 %idxprom3
  %idxprom5 = sext i32 %i.0.rewritten to i64
  %arrayidx6 = getelementptr inbounds [16 x i32], [16 x i32]* %arrayidx4, i64 0, i64 %idxprom5
  %6 = load i32, i32* %arrayidx6, align 4
  %idxprom7 = sext i32 %i.0.rewritten to i64
  %arrayidx8 = getelementptr inbounds [16 x i32], [16 x i32]* %dis, i64 0, i64 %idxprom7
  store i32 %6, i32* %arrayidx8, align 4
  br label %for.inc

for.inc:                                          ; preds = %for.body
  %7 = load i1, i1* %out.8, align 1
  %cond.fold31 = or i1 false, %7
  store i1 %cond.fold31, i1* %out.9, align 1
  %inc = add nsw i32 %i.0.rewritten, 1
  br label %for.cond, !llvm.loop !6

for.end:                                          ; preds = %for.cond
  %8 = load i1, i1* %out.7, align 1
  %9 = xor i1 %cmp, true
  %in.32 = and i1 %8, %9
  %cond.fold33 = or i1 false, %in.32
  store i1 %cond.fold33, i1* %out.10, align 1
  br label %for.cond10

for.cond10:                                       ; preds = %for.inc61, %for.end
  %bestj.0.rewritten = phi i32 [ -1, %for.end ], [ %bestj.1.lcssa.rewritten, %for.inc61 ]
  %i9.0.rewritten = phi i32 [ 0, %for.end ], [ %inc62, %for.inc61 ]
  %fwedge.taken1.rewritten = phi i1 [ true, %for.end ], [ false, %for.inc61 ]
  %exitpred.frozen2.rewritten = phi i1 [ %cmp11, %for.inc61 ], [ false, %for.end ]
  %10 = load i1, i1* %out.28, align 1
  %11 = load i1, i1* %out.10, align 1
  %fwcond.and.fwtaken34 = and i1 %fwedge.taken1.rewritten, %11
  %cond.fold35 = or i1 %fwcond.and.fwtaken34, %10
  store i1 %cond.fold35, i1* %out.11, align 1
  %cmp11 = icmp slt i32 %i9.0.rewritten, %n
  br i1 %cmp11, label %for.body12, label %for.end63

for.body12:                                       ; preds = %for.cond10
  %12 = load i1, i1* %out.11, align 1
  %in.36 = and i1 %12, %cmp11
  %cond.fold37 = or i1 false, %in.36
  store i1 %cond.fold37, i1* %out.12, align 1
  br label %for.cond13

for.cond13:                                       ; preds = %for.inc26, %for.body12
  %bestj.1.rewritten = phi i32 [ %bestj.0.rewritten, %for.body12 ], [ %phi.fold113, %for.inc26 ]
  %j.0.rewritten = phi i32 [ 0, %for.body12 ], [ %inc27, %for.inc26 ]
  %fwedge.taken3.rewritten = phi i1 [ true, %for.body12 ], [ false, %for.inc26 ]
  %exitpred.frozen4.rewritten = phi i1 [ %cmp14, %for.inc26 ], [ false, %for.body12 ]
  %13 = load i1, i1* %out.19, align 1
  %14 = load i1, i1* %out.12, align 1
  %fwcond.and.fwtaken38 = and i1 %fwedge.taken3.rewritten, %14
  %cond.fold39 = or i1 %fwcond.and.fwtaken38, %13
  store i1 %cond.fold39, i1* %out.13, align 1
  %cmp14 = icmp slt i32 %j.0.rewritten, %n
  br i1 %cmp14, label %for.body15, label %for.end28

for.body15:                                       ; preds = %for.cond13
  %15 = load i1, i1* %out.13, align 1
  %in.40 = and i1 %15, %cmp14
  %cond.fold41 = or i1 false, %in.40
  store i1 %cond.fold41, i1* %out.14, align 1
  %idxprom16 = sext i32 %j.0.rewritten to i64
  %arrayidx17 = getelementptr inbounds [16 x i32], [16 x i32]* %vis, i64 0, i64 %idxprom16
  %16 = load i32, i32* %arrayidx17, align 4
  %tobool = icmp ne i32 %16, 0
  br label %land.lhs.true

land.lhs.true:                                    ; preds = %for.body15
  %17 = load i1, i1* %out.14, align 1
  %18 = xor i1 %tobool, true
  %in.42 = and i1 %17, %18
  %cond.fold43 = or i1 false, %in.42
  store i1 %cond.fold43, i1* %out.15, align 1
  %19 = load i1, i1* %out.15, align 1
  %cmp18 = icmp slt i32 %bestj.1.rewritten, 0
  br label %lor.lhs.false

lor.lhs.false:                                    ; preds = %land.lhs.true
  %20 = load i1, i1* %out.15, align 1
  %21 = xor i1 %cmp18, true
  %in.44 = and i1 %20, %21
  %cond.fold45 = or i1 false, %in.44
  store i1 %cond.fold45, i1* %out.16, align 1
  %22 = load i1, i1* %out.16, align 1
  %idxprom19 = sext i32 %j.0.rewritten to i64
  %arrayidx20 = getelementptr inbounds [16 x i32], [16 x i32]* %dis, i64 0, i64 %idxprom19
  %idx1.safe82 = icmp slt i64 %idxprom19, 16
  %access.safe83 = and i1 true, %idx1.safe82
  %23 = or i1 %22, %access.safe83
  %24 = bitcast i64* %shadow to i32*
  %ctsel84 = select i1 %23, i32* %arrayidx20, i32* %24
  %25 = load i32, i32* %ctsel84, align 4
  %idxprom21 = sext i32 %bestj.1.rewritten to i64
  %arrayidx22 = getelementptr inbounds [16 x i32], [16 x i32]* %dis, i64 0, i64 %idxprom21
  %idx1.safe85 = icmp slt i64 %idxprom21, 16
  %access.safe86 = and i1 true, %idx1.safe85
  %26 = or i1 %22, %access.safe86
  %27 = bitcast i64* %shadow to i32*
  %ctsel87 = select i1 %26, i32* %arrayidx22, i32* %27
  %28 = load i32, i32* %ctsel87, align 4
  %cmp23 = icmp slt i32 %25, %28
  %29 = bitcast i64* %shadow to i1*
  %ctsel88 = select i1 %22, i1* %pred.alloca, i1* %29
  %30 = load i1, i1* %ctsel88, align 1
  %select.val.89 = select i1 %22, i1 %cmp23, i1 %30
  store i1 %select.val.89, i1* %ctsel88, align 1
  %31 = bitcast i64* %shadow to i1*
  %ctsel90 = select i1 %22, i1* %pred.alloca50, i1* %31
  %32 = load i1, i1* %ctsel90, align 1
  %select.val.91 = select i1 %22, i1 %cmp23, i1 %32
  store i1 %select.val.91, i1* %ctsel90, align 1
  br label %if.then

if.then:                                          ; preds = %lor.lhs.false
  %pred.load = load i1, i1* %pred.alloca, align 1
  %33 = load i1, i1* %out.16, align 1
  %in.46 = and i1 %33, %pred.load
  %34 = load i1, i1* %out.15, align 1
  %in.47 = and i1 %34, %cmp18
  %cond.fold48 = or i1 false, %in.47
  %cond.fold49 = or i1 %cond.fold48, %in.46
  store i1 %cond.fold49, i1* %out.17, align 1
  %35 = load i1, i1* %out.17, align 1
  %36 = bitcast i64* %shadow to i32*
  %ctsel = select i1 %35, i32* @x, i32* %36
  %37 = load i32, i32* %ctsel, align 4
  %add = add nsw i32 %j.0.rewritten, %37
  %idxprom24 = sext i32 %add to i64
  %arrayidx25 = getelementptr inbounds [16 x i32], [16 x i32]* %vis, i64 0, i64 %idxprom24
  %idx1.safe = icmp slt i64 %idxprom24, 16
  %access.safe = and i1 true, %idx1.safe
  %38 = or i1 %35, %access.safe
  %39 = bitcast i64* %shadow to i32*
  %ctsel81 = select i1 %38, i32* %arrayidx25, i32* %39
  %40 = load i32, i32* %ctsel81, align 4
  %select.val. = select i1 %35, i32 1, i32 %40
  store i32 %select.val., i32* %ctsel81, align 4
  br label %if.end

if.end:                                           ; preds = %if.then
  %bestj.2.rewritten = phi i32 [ %add, %if.then ]
  %pred.load51 = load i1, i1* %pred.alloca50, align 1
  %41 = load i1, i1* %out.17, align 1
  %42 = load i1, i1* %out.16, align 1
  %43 = xor i1 %pred.load51, true
  %in.52 = and i1 %42, %43
  %44 = load i1, i1* %out.14, align 1
  %in.53 = and i1 %44, %tobool
  %phi.fold = select i1 %in.53, i32 %bestj.1.rewritten, i32 %bestj.2.rewritten
  %phi.fold113 = select i1 %in.52, i32 %bestj.1.rewritten, i32 %phi.fold
  %cond.fold54 = or i1 false, %in.52
  %cond.fold55 = or i1 %cond.fold54, %in.53
  %cond.fold56 = or i1 %cond.fold55, %41
  store i1 %cond.fold56, i1* %out.18, align 1
  br label %for.inc26

for.inc26:                                        ; preds = %if.end
  %45 = load i1, i1* %out.18, align 1
  %cond.fold57 = or i1 false, %45
  store i1 %cond.fold57, i1* %out.19, align 1
  %inc27 = add nsw i32 %j.0.rewritten, 1
  br label %for.cond13, !llvm.loop !8

for.end28:                                        ; preds = %for.cond13
  %bestj.1.lcssa.rewritten = phi i32 [ %bestj.1.rewritten, %for.cond13 ]
  %46 = load i1, i1* %out.13, align 1
  %47 = xor i1 %cmp14, true
  %in.58 = and i1 %46, %47
  %cond.fold59 = or i1 false, %in.58
  store i1 %cond.fold59, i1* %out.20, align 1
  br label %for.cond30

for.cond30:                                       ; preds = %for.inc58, %for.end28
  %j29.0.rewritten = phi i32 [ 0, %for.end28 ], [ %inc59, %for.inc58 ]
  %fwedge.taken5.rewritten = phi i1 [ true, %for.end28 ], [ false, %for.inc58 ]
  %exitpred.frozen6.rewritten = phi i1 [ %cmp31, %for.inc58 ], [ false, %for.end28 ]
  %48 = load i1, i1* %out.26, align 1
  %49 = load i1, i1* %out.20, align 1
  %fwcond.and.fwtaken60 = and i1 %fwedge.taken5.rewritten, %49
  %cond.fold61 = or i1 %fwcond.and.fwtaken60, %48
  store i1 %cond.fold61, i1* %out.21, align 1
  %cmp31 = icmp slt i32 %j29.0.rewritten, %n
  br i1 %cmp31, label %for.body32, label %for.end60

for.body32:                                       ; preds = %for.cond30
  %50 = load i1, i1* %out.21, align 1
  %in.62 = and i1 %50, %cmp31
  %cond.fold63 = or i1 false, %in.62
  store i1 %cond.fold63, i1* %out.22, align 1
  %idxprom33 = sext i32 %j29.0.rewritten to i64
  %arrayidx34 = getelementptr inbounds [16 x i32], [16 x i32]* %vis, i64 0, i64 %idxprom33
  %51 = load i32, i32* %arrayidx34, align 4
  %tobool35 = icmp ne i32 %51, 0
  br label %land.lhs.true36

land.lhs.true36:                                  ; preds = %for.body32
  %52 = load i1, i1* %out.22, align 1
  %53 = xor i1 %tobool35, true
  %in.64 = and i1 %52, %53
  %cond.fold65 = or i1 false, %in.64
  store i1 %cond.fold65, i1* %out.23, align 1
  %54 = load i1, i1* %out.23, align 1
  %idxprom37 = sext i32 %bestj.1.lcssa.rewritten to i64
  %arrayidx38 = getelementptr inbounds [16 x i32], [16 x i32]* %dis, i64 0, i64 %idxprom37
  %idx1.safe92 = icmp slt i64 %idxprom37, 16
  %access.safe93 = and i1 true, %idx1.safe92
  %55 = or i1 %54, %access.safe93
  %56 = bitcast i64* %shadow to i32*
  %ctsel94 = select i1 %55, i32* %arrayidx38, i32* %56
  %57 = load i32, i32* %ctsel94, align 4
  %idxprom39 = sext i32 %bestj.1.lcssa.rewritten to i64
  %arrayidx40 = getelementptr inbounds [16 x i32], [16 x i32]* %e.unwrapped, i64 %idxprom39
  %idxprom41 = sext i32 %j29.0.rewritten to i64
  %arrayidx42 = getelementptr inbounds [16 x i32], [16 x i32]* %arrayidx40, i64 0, i64 %idxprom41
  %idx1.safe95 = icmp slt i64 %idxprom41, 16
  %access.safe96 = and i1 true, %idx1.safe95
  %58 = or i1 %54, %access.safe96
  %59 = bitcast i64* %shadow to i32*
  %ctsel97 = select i1 %58, i32* %arrayidx42, i32* %59
  %60 = load i32, i32* %ctsel97, align 4
  %add43 = add nsw i32 %57, %60
  %idxprom44 = sext i32 %j29.0.rewritten to i64
  %arrayidx45 = getelementptr inbounds [16 x i32], [16 x i32]* %dis, i64 0, i64 %idxprom44
  %idx1.safe98 = icmp slt i64 %idxprom44, 16
  %access.safe99 = and i1 true, %idx1.safe98
  %61 = or i1 %54, %access.safe99
  %62 = bitcast i64* %shadow to i32*
  %ctsel100 = select i1 %61, i32* %arrayidx45, i32* %62
  %63 = load i32, i32* %ctsel100, align 4
  %cmp46 = icmp slt i32 %add43, %63
  %64 = bitcast i64* %shadow to i1*
  %ctsel101 = select i1 %54, i1* %pred.alloca68, i1* %64
  %65 = load i1, i1* %ctsel101, align 1
  %select.val.102 = select i1 %54, i1 %cmp46, i1 %65
  store i1 %select.val.102, i1* %ctsel101, align 1
  br label %if.then47

if.then47:                                        ; preds = %land.lhs.true36
  %66 = load i1, i1* %out.23, align 1
  %in.66 = and i1 %66, %cmp46
  %cond.fold67 = or i1 false, %in.66
  store i1 %cond.fold67, i1* %out.24, align 1
  %67 = load i1, i1* %out.24, align 1
  %idxprom48 = sext i32 %bestj.1.lcssa.rewritten to i64
  %arrayidx49 = getelementptr inbounds [16 x i32], [16 x i32]* %dis, i64 0, i64 %idxprom48
  %idx1.safe103 = icmp slt i64 %idxprom48, 16
  %access.safe104 = and i1 true, %idx1.safe103
  %68 = or i1 %67, %access.safe104
  %69 = bitcast i64* %shadow to i32*
  %ctsel105 = select i1 %68, i32* %arrayidx49, i32* %69
  %70 = load i32, i32* %ctsel105, align 4
  %idxprom50 = sext i32 %bestj.1.lcssa.rewritten to i64
  %arrayidx51 = getelementptr inbounds [16 x i32], [16 x i32]* %e.unwrapped, i64 %idxprom50
  %idxprom52 = sext i32 %j29.0.rewritten to i64
  %arrayidx53 = getelementptr inbounds [16 x i32], [16 x i32]* %arrayidx51, i64 0, i64 %idxprom52
  %idx1.safe106 = icmp slt i64 %idxprom52, 16
  %access.safe107 = and i1 true, %idx1.safe106
  %71 = or i1 %67, %access.safe107
  %72 = bitcast i64* %shadow to i32*
  %ctsel108 = select i1 %71, i32* %arrayidx53, i32* %72
  %73 = load i32, i32* %ctsel108, align 4
  %add54 = add nsw i32 %70, %73
  %idxprom55 = sext i32 %j29.0.rewritten to i64
  %arrayidx56 = getelementptr inbounds [16 x i32], [16 x i32]* %dis, i64 0, i64 %idxprom55
  %idx1.safe109 = icmp slt i64 %idxprom55, 16
  %access.safe110 = and i1 true, %idx1.safe109
  %74 = or i1 %67, %access.safe110
  %75 = bitcast i64* %shadow to i32*
  %ctsel111 = select i1 %74, i32* %arrayidx56, i32* %75
  %76 = load i32, i32* %ctsel111, align 4
  %select.val.112 = select i1 %67, i32 %add54, i32 %76
  store i32 %select.val.112, i32* %ctsel111, align 4
  br label %if.end57

if.end57:                                         ; preds = %if.then47
  %pred.load69 = load i1, i1* %pred.alloca68, align 1
  %77 = load i1, i1* %out.24, align 1
  %78 = load i1, i1* %out.23, align 1
  %79 = xor i1 %pred.load69, true
  %in.70 = and i1 %78, %79
  %80 = load i1, i1* %out.22, align 1
  %in.71 = and i1 %80, %tobool35
  %cond.fold72 = or i1 false, %in.71
  %cond.fold73 = or i1 %cond.fold72, %in.70
  %cond.fold74 = or i1 %cond.fold73, %77
  store i1 %cond.fold74, i1* %out.25, align 1
  br label %for.inc58

for.inc58:                                        ; preds = %if.end57
  %81 = load i1, i1* %out.25, align 1
  %cond.fold75 = or i1 false, %81
  store i1 %cond.fold75, i1* %out.26, align 1
  %inc59 = add nsw i32 %j29.0.rewritten, 1
  br label %for.cond30, !llvm.loop !9

for.end60:                                        ; preds = %for.cond30
  %82 = load i1, i1* %out.21, align 1
  %83 = xor i1 %cmp31, true
  %in.76 = and i1 %82, %83
  %cond.fold77 = or i1 false, %in.76
  store i1 %cond.fold77, i1* %out.27, align 1
  br label %for.inc61

for.inc61:                                        ; preds = %for.end60
  %84 = load i1, i1* %out.27, align 1
  %cond.fold78 = or i1 false, %84
  store i1 %cond.fold78, i1* %out.28, align 1
  %inc62 = add nsw i32 %i9.0.rewritten, 1
  br label %for.cond10, !llvm.loop !10

for.end63:                                        ; preds = %for.cond10
  %85 = load i1, i1* %out.11, align 1
  %86 = xor i1 %cmp11, true
  %in.79 = and i1 %85, %86
  %cond.fold80 = or i1 false, %in.79
  store i1 %cond.fold80, i1* %out.29, align 1
  %idxprom64 = sext i32 %t to i64
  %arrayidx65 = getelementptr inbounds [16 x i32], [16 x i32]* %dis, i64 0, i64 %idxprom64
  %87 = load i32, i32* %arrayidx65, align 4
  ret i32 %87
}

; Function Attrs: inaccessiblememonly nofree nosync nounwind willreturn
declare void @llvm.var.annotation(i8*, i8*, i8*, i32, i8*) #1

; Function Attrs: argmemonly nofree nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1 immarg) #2

; Function Attrs: noinline nounwind sspstrong uwtable
define dso_local i32 @main() #0 {
entry:
  %arraydecay.wrapped = alloca %"[16 x i32]ptr.wrapped.ty", align 8
  %out. = alloca i1, align 1
  store i1 false, i1* %out., align 1
  %out.3 = alloca i1, align 1
  store i1 false, i1* %out.3, align 1
  %out.4 = alloca i1, align 1
  store i1 false, i1* %out.4, align 1
  %out.5 = alloca i1, align 1
  store i1 false, i1* %out.5, align 1
  %out.6 = alloca i1, align 1
  store i1 false, i1* %out.6, align 1
  %out.7 = alloca i1, align 1
  store i1 false, i1* %out.7, align 1
  %out.8 = alloca i1, align 1
  store i1 false, i1* %out.8, align 1
  %out.9 = alloca i1, align 1
  store i1 false, i1* %out.9, align 1
  %out.10 = alloca i1, align 1
  store i1 false, i1* %out.10, align 1
  %in = alloca [16 x [16 x i32]], align 16
  %r = alloca i32, align 4
  store i1 true, i1* %out., align 1
  store i1 false, i1* %out.7, align 1
  store i1 false, i1* %out.9, align 1
  %call = call i64 @read(i32 noundef 0, i8* noundef bitcast (i32* @x to i8*), i64 noundef 4)
  %0 = load i32, i32* @x, align 4
  %conv = trunc i32 %0 to i8
  %conv1 = zext i8 %conv to i32
  %1 = load i32, i32* @x, align 4
  %sub = sub nsw i32 %1, %conv1
  store i32 %sub, i32* @x, align 4
  %in2 = bitcast [16 x [16 x i32]]* %in to i8*
  call void @llvm.var.annotation(i8* %in2, i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str.3, i32 0, i32 0), i8* getelementptr inbounds ([11 x i8], [11 x i8]* @.str.1.4, i32 0, i32 0), i32 25, i8* null)
  %shadow = alloca i64, align 8
  store i64 0, i64* %shadow, align 8
  br label %for.cond

for.cond:                                         ; preds = %for.inc11, %entry
  %i.0.rewritten = phi i32 [ 0, %entry ], [ %inc12, %for.inc11 ]
  %fwedge.taken.rewritten = phi i1 [ true, %entry ], [ false, %for.inc11 ]
  %exitpred.frozen.rewritten = phi i1 [ %cmp, %for.inc11 ], [ false, %entry ]
  %2 = load i1, i1* %out.9, align 1
  %3 = load i1, i1* %out., align 1
  %fwcond.and.fwtaken = and i1 %fwedge.taken.rewritten, %3
  %cond.fold = or i1 %fwcond.and.fwtaken, %2
  store i1 %cond.fold, i1* %out.3, align 1
  %cmp = icmp slt i32 %i.0.rewritten, 16
  br i1 %cmp, label %for.body, label %for.end13

for.body:                                         ; preds = %for.cond
  %4 = load i1, i1* %out.3, align 1
  %in. = and i1 %4, %cmp
  %cond.fold11 = or i1 false, %in.
  store i1 %cond.fold11, i1* %out.4, align 1
  br label %for.cond4

for.cond4:                                        ; preds = %for.inc, %for.body
  %j.0.rewritten = phi i32 [ 0, %for.body ], [ %inc, %for.inc ]
  %fwedge.taken1.rewritten = phi i1 [ true, %for.body ], [ false, %for.inc ]
  %exitpred.frozen2.rewritten = phi i1 [ %cmp5, %for.inc ], [ false, %for.body ]
  %5 = load i1, i1* %out.7, align 1
  %6 = load i1, i1* %out.4, align 1
  %fwcond.and.fwtaken12 = and i1 %fwedge.taken1.rewritten, %6
  %cond.fold13 = or i1 %fwcond.and.fwtaken12, %5
  store i1 %cond.fold13, i1* %out.5, align 1
  %cmp5 = icmp slt i32 %j.0.rewritten, 16
  br i1 %cmp5, label %for.body7, label %for.end

for.body7:                                        ; preds = %for.cond4
  %7 = load i1, i1* %out.5, align 1
  %in.14 = and i1 %7, %cmp5
  %cond.fold15 = or i1 false, %in.14
  store i1 %cond.fold15, i1* %out.6, align 1
  %idxprom = sext i32 %i.0.rewritten to i64
  %arrayidx = getelementptr inbounds [16 x [16 x i32]], [16 x [16 x i32]]* %in, i64 0, i64 %idxprom
  %idxprom8 = sext i32 %j.0.rewritten to i64
  %arrayidx9 = getelementptr inbounds [16 x i32], [16 x i32]* %arrayidx, i64 0, i64 %idxprom8
  %8 = bitcast i32* %arrayidx9 to i8*
  %call10 = call i64 @read(i32 noundef 0, i8* noundef %8, i64 noundef 4)
  br label %for.inc

for.inc:                                          ; preds = %for.body7
  %9 = load i1, i1* %out.6, align 1
  %cond.fold16 = or i1 false, %9
  store i1 %cond.fold16, i1* %out.7, align 1
  %inc = add nsw i32 %j.0.rewritten, 1
  br label %for.cond4, !llvm.loop !11

for.end:                                          ; preds = %for.cond4
  %10 = load i1, i1* %out.5, align 1
  %11 = xor i1 %cmp5, true
  %in.17 = and i1 %10, %11
  %cond.fold18 = or i1 false, %in.17
  store i1 %cond.fold18, i1* %out.8, align 1
  br label %for.inc11

for.inc11:                                        ; preds = %for.end
  %12 = load i1, i1* %out.8, align 1
  %cond.fold19 = or i1 false, %12
  store i1 %cond.fold19, i1* %out.9, align 1
  %inc12 = add nsw i32 %i.0.rewritten, 1
  br label %for.cond, !llvm.loop !12

for.end13:                                        ; preds = %for.cond
  %13 = load i1, i1* %out.3, align 1
  %14 = xor i1 %cmp, true
  %in.20 = and i1 %13, %14
  %cond.fold21 = or i1 false, %in.20
  store i1 %cond.fold21, i1* %out.10, align 1
  %arraydecay = getelementptr inbounds [16 x [16 x i32]], [16 x [16 x i32]]* %in, i64 0, i64 0
  %arraydecay.unwrapped = getelementptr inbounds %"[16 x i32]ptr.wrapped.ty", %"[16 x i32]ptr.wrapped.ty"* %arraydecay.wrapped, i32 0, i32 0
  %arraydecay.wrapped.field0.length.ptr = getelementptr inbounds %"[16 x i32]ptr.wrapped.ty", %"[16 x i32]ptr.wrapped.ty"* %arraydecay.wrapped, i32 0, i32 1
  store i64 256, i64* %arraydecay.wrapped.field0.length.ptr, align 8
  store [16 x i32]* %arraydecay, [16 x i32]** %arraydecay.unwrapped, align 8
  %call14 = call i32 @dijkstra(i32 16, i32 0, i32 15, %"[16 x i32]ptr.wrapped.ty"* %arraydecay.wrapped)
  store i32 %call14, i32* %r, align 4
  %15 = bitcast i32* %r to i8*
  %call15 = call i64 @write(i32 noundef 1, i8* noundef %15, i64 noundef 4)
  ret i32 0
}

declare i64 @read(i32 noundef, i8* noundef, i64 noundef) #3

declare i64 @write(i32 noundef, i8* noundef, i64 noundef) #3

attributes #0 = { noinline nounwind sspstrong uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { inaccessiblememonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nounwind willreturn writeonly }
attributes #3 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

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
!10 = distinct !{!10, !7}
!11 = distinct !{!11, !7}
!12 = distinct !{!12, !7}
