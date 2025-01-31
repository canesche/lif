; ModuleID = 'llvm-ir/histogram.ll'
source_filename = "lib/histogram.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [4 x i8] c"%d\0A\00", align 1

; Function Attrs: noinline nounwind sspstrong uwtable
define dso_local void @histogram(i32* noundef %a, i32* noundef %c) #0 {
entry:
  %foo = alloca i32, align 4
  %_zzq_args = alloca [6 x i64], align 16
  %_zzq_result = alloca i64, align 8
  br label %for.cond

for.cond:                                         ; preds = %for.inc, %entry
  %i.0 = phi i32 [ 0, %entry ], [ %inc, %for.inc ]
  %cmp = icmp slt i32 %i.0, 1000
  br i1 %cmp, label %for.body, label %for.end

for.body:                                         ; preds = %for.cond
  %idxprom = sext i32 %i.0 to i64
  %arrayidx = getelementptr inbounds i32, i32* %c, i64 %idxprom
  store i32 0, i32* %arrayidx, align 4
  br label %for.inc

for.inc:                                          ; preds = %for.body
  %inc = add nsw i32 %i.0, 1
  br label %for.cond, !llvm.loop !6

for.end:                                          ; preds = %for.cond
  br label %for.cond1

for.cond1:                                        ; preds = %for.inc20, %for.end
  %i.1 = phi i32 [ 0, %for.end ], [ %inc21, %for.inc20 ]
  %cmp2 = icmp slt i32 %i.1, 1000
  br i1 %cmp2, label %for.body3, label %for.end22

for.body3:                                        ; preds = %for.cond1
  %idxprom4 = sext i32 %i.1 to i64
  %arrayidx5 = getelementptr inbounds i32, i32* %a, i64 %idxprom4
  %0 = load i32, i32* %arrayidx5, align 4
  store i32 0, i32* %foo, align 4
  %cmp6 = icmp sgt i32 %0, 0
  br i1 %cmp6, label %if.then, label %if.else

if.then:                                          ; preds = %for.body3
  %1 = load i32, i32* %foo, align 4
  %inc7 = add nsw i32 %1, 1
  store i32 %inc7, i32* %foo, align 4
  %rem = srem i32 %0, 1000
  br label %if.end

if.else:                                          ; preds = %for.body3
  %sub = sub nsw i32 0, %0
  %rem8 = srem i32 %sub, 1000
  br label %if.end

if.end:                                           ; preds = %if.else, %if.then
  %t.0 = phi i32 [ %rem, %if.then ], [ %rem8, %if.else ]
  %arrayidx9 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args, i64 0, i64 0
  store volatile i64 1296236546, i64* %arrayidx9, align 16
  %2 = ptrtoint i32* %foo to i64
  %arrayidx10 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args, i64 0, i64 1
  store volatile i64 %2, i64* %arrayidx10, align 8
  %arrayidx11 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args, i64 0, i64 2
  store volatile i64 4, i64* %arrayidx11, align 16
  %arrayidx12 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args, i64 0, i64 3
  store volatile i64 0, i64* %arrayidx12, align 8
  %arrayidx13 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args, i64 0, i64 4
  store volatile i64 0, i64* %arrayidx13, align 16
  %arrayidx14 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args, i64 0, i64 5
  store volatile i64 0, i64* %arrayidx14, align 8
  %arrayidx15 = getelementptr inbounds [6 x i64], [6 x i64]* %_zzq_args, i64 0, i64 0
  %3 = call i64 asm sideeffect "rolq $$3,  %rdi ; rolq $$13, %rdi\0A\09rolq $$61, %rdi ; rolq $$51, %rdi\0A\09xchgq %rbx,%rbx", "={dx},{ax},0,~{cc},~{memory},~{dirflag},~{fpsr},~{flags}"(i64* %arrayidx15, i64 0) #2, !srcloc !8
  store volatile i64 %3, i64* %_zzq_result, align 8
  %4 = load volatile i64, i64* %_zzq_result, align 8
  %5 = load i32, i32* %foo, align 4
  %call = call i32 (i8*, ...) @printf(i8* noundef getelementptr inbounds ([4 x i8], [4 x i8]* @.str, i64 0, i64 0), i32 noundef %5)
  %idxprom16 = sext i32 %t.0 to i64
  %arrayidx17 = getelementptr inbounds i32, i32* %c, i64 %idxprom16
  %6 = load i32, i32* %arrayidx17, align 4
  %add = add nsw i32 %6, 1
  %idxprom18 = sext i32 %t.0 to i64
  %arrayidx19 = getelementptr inbounds i32, i32* %c, i64 %idxprom18
  store i32 %add, i32* %arrayidx19, align 4
  br label %for.inc20

for.inc20:                                        ; preds = %if.end
  %inc21 = add nsw i32 %i.1, 1
  br label %for.cond1, !llvm.loop !9

for.end22:                                        ; preds = %for.cond1
  ret void
}

declare i32 @printf(i8* noundef, ...) #1

attributes #0 = { noinline nounwind sspstrong uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { nounwind }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 7, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 1}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"clang version 14.0.6"}
!6 = distinct !{!6, !7}
!7 = !{!"llvm.loop.mustprogress"}
!8 = !{i64 2148084668, i64 2148084704, i64 2148084772}
!9 = distinct !{!9, !7}
