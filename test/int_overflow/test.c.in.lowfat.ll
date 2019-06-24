; ModuleID = 'test.c'
source_filename = "test.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@.src = private unnamed_addr constant [7 x i8] c"test.c\00", align 1
@0 = private unnamed_addr constant { i16, i16, [6 x i8] } { i16 0, i16 11, [6 x i8] c"'int'\00" }
@1 = private unnamed_addr global { { [7 x i8]*, i32, i32 }, { i16, i16, [6 x i8] }* } { { [7 x i8]*, i32, i32 } { [7 x i8]* @.src, i32 5, i32 5 }, { i16, i16, [6 x i8] }* @0 }

; Function Attrs: noinline nounwind uwtable
define i32 @main(i32, i8**) #0 !dbg !6 {
  call void @llvm.dbg.value(metadata i32 %0, i64 0, metadata !13, metadata !14), !dbg !15
  call void @llvm.dbg.value(metadata i8** %1, i64 0, metadata !16, metadata !14), !dbg !17
  call void @llvm.dbg.value(metadata i32 2147483647, i64 0, metadata !18, metadata !14), !dbg !19
  %3 = call { i32, i1 } @llvm.sadd.with.overflow.i32(i32 2147483647, i32 %0), !dbg !20
  %4 = extractvalue { i32, i1 } %3, 0, !dbg !20
  %5 = extractvalue { i32, i1 } %3, 1, !dbg !20
  %6 = xor i1 %5, true, !dbg !20, !nosanitize !2
  br i1 %6, label %10, label %7, !dbg !20, !prof !21, !nosanitize !2

; <label>:7:                                      ; preds = %2
  %8 = zext i32 2147483647 to i64, !dbg !22, !nosanitize !2
  %9 = zext i32 %0 to i64, !dbg !22, !nosanitize !2
  call void @__ubsan_handle_add_overflow(i8* bitcast ({ { [7 x i8]*, i32, i32 }, { i16, i16, [6 x i8] }* }* @1 to i8*), i64 %8, i64 %9) #3, !dbg !22, !nosanitize !2
  br label %10, !dbg !22, !nosanitize !2

; <label>:10:                                     ; preds = %7, %2
  call void @llvm.dbg.value(metadata i32 %4, i64 0, metadata !18, metadata !14), !dbg !19
  ret i32 0, !dbg !24
}

; Function Attrs: nounwind readnone
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: nounwind readnone
declare { i32, i1 } @llvm.sadd.with.overflow.i32(i32, i32) #1

; Function Attrs: uwtable
declare void @__ubsan_handle_add_overflow(i8*, i64, i64) #2

; Function Attrs: nounwind readnone
declare void @llvm.dbg.value(metadata, i64, metadata, metadata) #1

attributes #0 = { noinline nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+bmi,+bmi2,+fxsr,+lzcnt,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nounwind readnone }
attributes #2 = { uwtable }
attributes #3 = { nounwind }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!3, !4}
!llvm.ident = !{!5}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "clang version 4.0.0 (tags/RELEASE_400/final)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, enums: !2)
!1 = !DIFile(filename: "test.c", directory: "/home/nightwish/workspace/bug_repair/LowFat/test/int_overflow")
!2 = !{}
!3 = !{i32 2, !"Dwarf Version", i32 4}
!4 = !{i32 2, !"Debug Info Version", i32 3}
!5 = !{!"clang version 4.0.0 (tags/RELEASE_400/final)"}
!6 = distinct !DISubprogram(name: "main", scope: !1, file: !1, line: 3, type: !7, isLocal: false, isDefinition: true, scopeLine: 3, flags: DIFlagPrototyped, isOptimized: false, unit: !0, variables: !2)
!7 = !DISubroutineType(types: !8)
!8 = !{!9, !9, !10}
!9 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!10 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !11, size: 64)
!11 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !12, size: 64)
!12 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!13 = !DILocalVariable(name: "argc", arg: 1, scope: !6, file: !1, line: 3, type: !9)
!14 = !DIExpression()
!15 = !DILocation(line: 3, column: 14, scope: !6)
!16 = !DILocalVariable(name: "argv", arg: 2, scope: !6, file: !1, line: 3, type: !10)
!17 = !DILocation(line: 3, column: 27, scope: !6)
!18 = !DILocalVariable(name: "k", scope: !6, file: !1, line: 4, type: !9)
!19 = !DILocation(line: 4, column: 7, scope: !6)
!20 = !DILocation(line: 5, column: 5, scope: !6)
!21 = !{!"branch_weights", i32 1048575, i32 1}
!22 = !DILocation(line: 5, column: 5, scope: !23)
!23 = !DILexicalBlockFile(scope: !6, file: !1, discriminator: 1)
!24 = !DILocation(line: 8, column: 3, scope: !6)
