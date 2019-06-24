; ModuleID = 'flow.c'
source_filename = "flow.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@.str = private unnamed_addr constant [4 x i8] c"%u\0A\00", align 1
@.str.1 = private unnamed_addr constant [4 x i8] c"%d\0A\00", align 1

; Function Attrs: noinline nounwind uwtable
define i32 @signed_minus(i32, i32) #0 !dbg !7 {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  store i32 %0, i32* %3, align 4
  call void @llvm.dbg.declare(metadata i32* %3, metadata !11, metadata !DIExpression()), !dbg !12
  store i32 %1, i32* %4, align 4
  call void @llvm.dbg.declare(metadata i32* %4, metadata !13, metadata !DIExpression()), !dbg !14
  %5 = load i32, i32* %3, align 4, !dbg !15
  %6 = load i32, i32* %4, align 4, !dbg !16
  %7 = sub nsw i32 %5, %6, !dbg !17
  ret i32 %7, !dbg !18
}

; Function Attrs: nounwind readnone speculatable
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: noinline nounwind uwtable
define i32 @unsigned_minus(i32, i32) #0 !dbg !19 {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  store i32 %0, i32* %3, align 4
  call void @llvm.dbg.declare(metadata i32* %3, metadata !23, metadata !DIExpression()), !dbg !24
  store i32 %1, i32* %4, align 4
  call void @llvm.dbg.declare(metadata i32* %4, metadata !25, metadata !DIExpression()), !dbg !26
  %5 = load i32, i32* %3, align 4, !dbg !27
  %6 = load i32, i32* %4, align 4, !dbg !28
  %7 = sub i32 %5, %6, !dbg !29
  ret i32 %7, !dbg !30
}

; Function Attrs: noinline nounwind uwtable
define i32 @main() #0 !dbg !31 {
  %1 = alloca i32, align 4
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  store i32 0, i32* %1, align 4
  call void @llvm.dbg.declare(metadata i32* %2, metadata !34, metadata !DIExpression()), !dbg !35
  %4 = call i32 @unsigned_minus(i32 1, i32 3), !dbg !36
  store i32 %4, i32* %2, align 4, !dbg !35
  %5 = load i32, i32* %2, align 4, !dbg !37
  %6 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str, i32 0, i32 0), i32 %5), !dbg !38
  call void @llvm.dbg.declare(metadata i32* %3, metadata !39, metadata !DIExpression()), !dbg !40
  %7 = call i32 @signed_minus(i32 1, i32 3), !dbg !41
  store i32 %7, i32* %3, align 4, !dbg !40
  %8 = load i32, i32* %3, align 4, !dbg !42
  %9 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str.1, i32 0, i32 0), i32 %8), !dbg !43
  ret i32 0, !dbg !44
}

declare i32 @printf(i8*, ...) #2

attributes #0 = { noinline nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nounwind readnone speculatable }
attributes #2 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!3, !4, !5}
!llvm.ident = !{!6}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "clang version 6.0.1 ", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, enums: !2)
!1 = !DIFile(filename: "flow.c", directory: "/home/nightwish/workspace/bug_repair/LowFat/test/int_overflow")
!2 = !{}
!3 = !{i32 2, !"Dwarf Version", i32 4}
!4 = !{i32 2, !"Debug Info Version", i32 3}
!5 = !{i32 1, !"wchar_size", i32 4}
!6 = !{!"clang version 6.0.1 "}
!7 = distinct !DISubprogram(name: "signed_minus", scope: !1, file: !1, line: 4, type: !8, isLocal: false, isDefinition: true, scopeLine: 4, flags: DIFlagPrototyped, isOptimized: false, unit: !0, variables: !2)
!8 = !DISubroutineType(types: !9)
!9 = !{!10, !10, !10}
!10 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!11 = !DILocalVariable(name: "a", arg: 1, scope: !7, file: !1, line: 4, type: !10)
!12 = !DILocation(line: 4, column: 22, scope: !7)
!13 = !DILocalVariable(name: "b", arg: 2, scope: !7, file: !1, line: 4, type: !10)
!14 = !DILocation(line: 4, column: 29, scope: !7)
!15 = !DILocation(line: 5, column: 9, scope: !7)
!16 = !DILocation(line: 5, column: 13, scope: !7)
!17 = !DILocation(line: 5, column: 11, scope: !7)
!18 = !DILocation(line: 5, column: 2, scope: !7)
!19 = distinct !DISubprogram(name: "unsigned_minus", scope: !1, file: !1, line: 8, type: !20, isLocal: false, isDefinition: true, scopeLine: 8, flags: DIFlagPrototyped, isOptimized: false, unit: !0, variables: !2)
!20 = !DISubroutineType(types: !21)
!21 = !{!22, !22, !22}
!22 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!23 = !DILocalVariable(name: "a", arg: 1, scope: !19, file: !1, line: 8, type: !22)
!24 = !DILocation(line: 8, column: 42, scope: !19)
!25 = !DILocalVariable(name: "b", arg: 2, scope: !19, file: !1, line: 8, type: !22)
!26 = !DILocation(line: 8, column: 58, scope: !19)
!27 = !DILocation(line: 9, column: 9, scope: !19)
!28 = !DILocation(line: 9, column: 13, scope: !19)
!29 = !DILocation(line: 9, column: 11, scope: !19)
!30 = !DILocation(line: 9, column: 2, scope: !19)
!31 = distinct !DISubprogram(name: "main", scope: !1, file: !1, line: 12, type: !32, isLocal: false, isDefinition: true, scopeLine: 12, isOptimized: false, unit: !0, variables: !2)
!32 = !DISubroutineType(types: !33)
!33 = !{!10}
!34 = !DILocalVariable(name: "u", scope: !31, file: !1, line: 14, type: !22)
!35 = !DILocation(line: 14, column: 15, scope: !31)
!36 = !DILocation(line: 14, column: 19, scope: !31)
!37 = !DILocation(line: 16, column: 17, scope: !31)
!38 = !DILocation(line: 16, column: 2, scope: !31)
!39 = !DILocalVariable(name: "s", scope: !31, file: !1, line: 18, type: !10)
!40 = !DILocation(line: 18, column: 6, scope: !31)
!41 = !DILocation(line: 18, column: 10, scope: !31)
!42 = !DILocation(line: 20, column: 17, scope: !31)
!43 = !DILocation(line: 20, column: 2, scope: !31)
!44 = !DILocation(line: 22, column: 2, scope: !31)
