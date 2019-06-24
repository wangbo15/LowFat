; ModuleID = 'flow.c'
source_filename = "flow.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@.src = private unnamed_addr constant [7 x i8] c"flow.c\00", align 1
@0 = private unnamed_addr constant { i16, i16, [6 x i8] } { i16 0, i16 11, [6 x i8] c"'int'\00" }
@1 = private unnamed_addr global { { [7 x i8]*, i32, i32 }, { i16, i16, [6 x i8] }* } { { [7 x i8]*, i32, i32 } { [7 x i8]* @.src, i32 5, i32 11 }, { i16, i16, [6 x i8] }* @0 }
@2 = private unnamed_addr global { { [7 x i8]*, i32, i32 }, { i16, i16, [6 x i8] }* } { { [7 x i8]*, i32, i32 } { [7 x i8]* @.src, i32 13, i32 11 }, { i16, i16, [6 x i8] }* @0 }
@.str = private unnamed_addr constant [4 x i8] c"%u\0A\00", align 1
@.str.1 = private unnamed_addr constant [4 x i8] c"%d\0A\00", align 1

; Function Attrs: noinline nounwind uwtable
define i32 @signed_minus(i32, i32) #0 !dbg !6 {
  call void @llvm.dbg.value(metadata i32 %0, i64 0, metadata !10, metadata !11), !dbg !12
  call void @llvm.dbg.value(metadata i32 %1, i64 0, metadata !13, metadata !11), !dbg !14
  %3 = call { i32, i1 } @llvm.ssub.with.overflow.i32(i32 %0, i32 %1), !dbg !15
  %4 = extractvalue { i32, i1 } %3, 0, !dbg !15
  %5 = extractvalue { i32, i1 } %3, 1, !dbg !15
  %6 = xor i1 %5, true, !dbg !15, !nosanitize !2
  br i1 %6, label %10, label %7, !dbg !15, !prof !16, !nosanitize !2

; <label>:7:                                      ; preds = %2
  %8 = zext i32 %0 to i64, !dbg !17, !nosanitize !2
  %9 = zext i32 %1 to i64, !dbg !17, !nosanitize !2
  call void @__ubsan_handle_sub_overflow(i8* bitcast ({ { [7 x i8]*, i32, i32 }, { i16, i16, [6 x i8] }* }* @1 to i8*), i64 %8, i64 %9) #4, !dbg !17, !nosanitize !2
  br label %10, !dbg !17, !nosanitize !2

; <label>:10:                                     ; preds = %7, %2
  ret i32 %4, !dbg !19
}

; Function Attrs: nounwind readnone
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: nounwind readnone
declare { i32, i1 } @llvm.ssub.with.overflow.i32(i32, i32) #1

; Function Attrs: uwtable
declare void @__ubsan_handle_sub_overflow(i8*, i64, i64) #2

; Function Attrs: noinline nounwind uwtable
define i32 @unsigned_minus(i32, i32) #0 !dbg !21 {
  call void @llvm.dbg.value(metadata i32 %0, i64 0, metadata !25, metadata !11), !dbg !26
  call void @llvm.dbg.value(metadata i32 %1, i64 0, metadata !27, metadata !11), !dbg !28
  %3 = sub i32 %0, %1, !dbg !29
  ret i32 %3, !dbg !30
}

; Function Attrs: noinline nounwind uwtable
define i32 @signed_add(i32, i32) #0 !dbg !31 {
  call void @llvm.dbg.value(metadata i32 %0, i64 0, metadata !32, metadata !11), !dbg !33
  call void @llvm.dbg.value(metadata i32 %1, i64 0, metadata !34, metadata !11), !dbg !35
  %3 = call { i32, i1 } @llvm.sadd.with.overflow.i32(i32 %0, i32 %1), !dbg !36
  %4 = extractvalue { i32, i1 } %3, 0, !dbg !36
  %5 = extractvalue { i32, i1 } %3, 1, !dbg !36
  %6 = xor i1 %5, true, !dbg !36, !nosanitize !2
  br i1 %6, label %10, label %7, !dbg !36, !prof !16, !nosanitize !2

; <label>:7:                                      ; preds = %2
  %8 = zext i32 %0 to i64, !dbg !37, !nosanitize !2
  %9 = zext i32 %1 to i64, !dbg !37, !nosanitize !2
  call void @__ubsan_handle_add_overflow(i8* bitcast ({ { [7 x i8]*, i32, i32 }, { i16, i16, [6 x i8] }* }* @2 to i8*), i64 %8, i64 %9) #4, !dbg !37, !nosanitize !2
  br label %10, !dbg !37, !nosanitize !2

; <label>:10:                                     ; preds = %7, %2
  ret i32 %4, !dbg !39
}

; Function Attrs: nounwind readnone
declare { i32, i1 } @llvm.sadd.with.overflow.i32(i32, i32) #1

; Function Attrs: uwtable
declare void @__ubsan_handle_add_overflow(i8*, i64, i64) #2

; Function Attrs: noinline nounwind uwtable
define i32 @unsigned_add(i32, i32) #0 !dbg !41 {
  call void @llvm.dbg.value(metadata i32 %0, i64 0, metadata !42, metadata !11), !dbg !43
  call void @llvm.dbg.value(metadata i32 %1, i64 0, metadata !44, metadata !11), !dbg !45
  %3 = add i32 %0, %1, !dbg !46
  ret i32 %3, !dbg !47
}

; Function Attrs: noinline nounwind uwtable
define i32 @main() #0 !dbg !48 {
  %1 = call i32 @unsigned_add(i32 1, i32 2147483647), !dbg !51
  call void @llvm.dbg.value(metadata i32 %1, i64 0, metadata !52, metadata !11), !dbg !53
  %2 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str, i32 0, i32 0), i32 %1), !dbg !54
  %3 = call i32 @signed_add(i32 1, i32 2147483647), !dbg !55
  call void @llvm.dbg.value(metadata i32 %3, i64 0, metadata !56, metadata !11), !dbg !57
  %4 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str.1, i32 0, i32 0), i32 %3), !dbg !58
  ret i32 0, !dbg !59
}

declare i32 @printf(i8*, ...) #3

; Function Attrs: nounwind readnone
declare void @llvm.dbg.value(metadata, i64, metadata, metadata) #1

attributes #0 = { noinline nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+bmi,+bmi2,+fxsr,+lzcnt,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nounwind readnone }
attributes #2 = { uwtable }
attributes #3 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+bmi,+bmi2,+fxsr,+lzcnt,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #4 = { nounwind }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!3, !4}
!llvm.ident = !{!5}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "clang version 4.0.0 (tags/RELEASE_400/final)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, enums: !2)
!1 = !DIFile(filename: "flow.c", directory: "/home/nightwish/workspace/bug_repair/LowFat/test/int_overflow")
!2 = !{}
!3 = !{i32 2, !"Dwarf Version", i32 4}
!4 = !{i32 2, !"Debug Info Version", i32 3}
!5 = !{!"clang version 4.0.0 (tags/RELEASE_400/final)"}
!6 = distinct !DISubprogram(name: "signed_minus", scope: !1, file: !1, line: 4, type: !7, isLocal: false, isDefinition: true, scopeLine: 4, flags: DIFlagPrototyped, isOptimized: false, unit: !0, variables: !2)
!7 = !DISubroutineType(types: !8)
!8 = !{!9, !9, !9}
!9 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!10 = !DILocalVariable(name: "a", arg: 1, scope: !6, file: !1, line: 4, type: !9)
!11 = !DIExpression()
!12 = !DILocation(line: 4, column: 22, scope: !6)
!13 = !DILocalVariable(name: "b", arg: 2, scope: !6, file: !1, line: 4, type: !9)
!14 = !DILocation(line: 4, column: 29, scope: !6)
!15 = !DILocation(line: 5, column: 11, scope: !6)
!16 = !{!"branch_weights", i32 1048575, i32 1}
!17 = !DILocation(line: 5, column: 11, scope: !18)
!18 = !DILexicalBlockFile(scope: !6, file: !1, discriminator: 1)
!19 = !DILocation(line: 5, column: 2, scope: !20)
!20 = !DILexicalBlockFile(scope: !6, file: !1, discriminator: 2)
!21 = distinct !DISubprogram(name: "unsigned_minus", scope: !1, file: !1, line: 8, type: !22, isLocal: false, isDefinition: true, scopeLine: 8, flags: DIFlagPrototyped, isOptimized: false, unit: !0, variables: !2)
!22 = !DISubroutineType(types: !23)
!23 = !{!24, !24, !24}
!24 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!25 = !DILocalVariable(name: "a", arg: 1, scope: !21, file: !1, line: 8, type: !24)
!26 = !DILocation(line: 8, column: 42, scope: !21)
!27 = !DILocalVariable(name: "b", arg: 2, scope: !21, file: !1, line: 8, type: !24)
!28 = !DILocation(line: 8, column: 58, scope: !21)
!29 = !DILocation(line: 9, column: 11, scope: !21)
!30 = !DILocation(line: 9, column: 2, scope: !21)
!31 = distinct !DISubprogram(name: "signed_add", scope: !1, file: !1, line: 12, type: !7, isLocal: false, isDefinition: true, scopeLine: 12, flags: DIFlagPrototyped, isOptimized: false, unit: !0, variables: !2)
!32 = !DILocalVariable(name: "a", arg: 1, scope: !31, file: !1, line: 12, type: !9)
!33 = !DILocation(line: 12, column: 20, scope: !31)
!34 = !DILocalVariable(name: "b", arg: 2, scope: !31, file: !1, line: 12, type: !9)
!35 = !DILocation(line: 12, column: 27, scope: !31)
!36 = !DILocation(line: 13, column: 11, scope: !31)
!37 = !DILocation(line: 13, column: 11, scope: !38)
!38 = !DILexicalBlockFile(scope: !31, file: !1, discriminator: 1)
!39 = !DILocation(line: 13, column: 2, scope: !40)
!40 = !DILexicalBlockFile(scope: !31, file: !1, discriminator: 2)
!41 = distinct !DISubprogram(name: "unsigned_add", scope: !1, file: !1, line: 16, type: !22, isLocal: false, isDefinition: true, scopeLine: 16, flags: DIFlagPrototyped, isOptimized: false, unit: !0, variables: !2)
!42 = !DILocalVariable(name: "a", arg: 1, scope: !41, file: !1, line: 16, type: !24)
!43 = !DILocation(line: 16, column: 40, scope: !41)
!44 = !DILocalVariable(name: "b", arg: 2, scope: !41, file: !1, line: 16, type: !24)
!45 = !DILocation(line: 16, column: 56, scope: !41)
!46 = !DILocation(line: 17, column: 11, scope: !41)
!47 = !DILocation(line: 17, column: 2, scope: !41)
!48 = distinct !DISubprogram(name: "main", scope: !1, file: !1, line: 20, type: !49, isLocal: false, isDefinition: true, scopeLine: 20, isOptimized: false, unit: !0, variables: !2)
!49 = !DISubroutineType(types: !50)
!50 = !{!9}
!51 = !DILocation(line: 22, column: 19, scope: !48)
!52 = !DILocalVariable(name: "u", scope: !48, file: !1, line: 22, type: !24)
!53 = !DILocation(line: 22, column: 15, scope: !48)
!54 = !DILocation(line: 24, column: 2, scope: !48)
!55 = !DILocation(line: 26, column: 10, scope: !48)
!56 = !DILocalVariable(name: "s", scope: !48, file: !1, line: 26, type: !9)
!57 = !DILocation(line: 26, column: 6, scope: !48)
!58 = !DILocation(line: 28, column: 2, scope: !48)
!59 = !DILocation(line: 30, column: 2, scope: !48)
