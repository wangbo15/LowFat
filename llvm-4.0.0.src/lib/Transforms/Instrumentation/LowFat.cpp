/*
 *   _|                                      _|_|_|_|            _|
 *   _|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
 *   _|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
 *   _|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
 *   _|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|
 * 
 * Gregory J. Duck.
 *
 * Copyright (c) 2018 The National University of Singapore.
 * All rights reserved.
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See the LICENSE file for details.
 */

#include <assert.h>
#include <stdio.h>

#include <iostream>
#include <map>
#include <vector>
#include <set>

#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/TypeBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/DiagnosticPrinter.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"

#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Constants.h"


#include "llvm/IR/Metadata.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/IR/ConstantRange.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/ValueHandle.h"


extern "C"
{
#include "lowfat_config.inc"
#include "lowfat.h"

#include "lowfat_ds.h"
}

using namespace llvm;
using namespace std;

/*
 * Type decls.
 */
typedef vector<tuple<Instruction *, Value *, unsigned>> Plan;
typedef map<Value *, Value *> PtrInfo;

/*
 * A bounds object represents a range lb..ub.  As a simplification, the lower
 * bounds is always fixed to (0) since 99% of the time this is sufficient.
 */
struct Bounds
{
    static const int64_t NONFAT_BOUND  = INT64_MAX;
    static const int64_t UNKNOWN_BOUND = INT64_MIN;

    static const int64_t lb = 0;
    int64_t ub;

    Bounds() : ub(0)
    {

    }

    Bounds(size_t lb, size_t ub) : ub(ub)
    {
        if (lb != 0)
            ub = UNKNOWN_BOUND;
    }

    static Bounds empty()
    {
        return Bounds();
    }

    static Bounds nonFat()
    {
        return Bounds(0, NONFAT_BOUND);
    }

    static Bounds unknown()
    {
        return Bounds(0, UNKNOWN_BOUND);
    }

    bool isUnknown()
    {
        return (ub == UNKNOWN_BOUND);
    }

    bool isNonFat()
    {
        return (ub == NONFAT_BOUND);
    }

    bool isInBounds(int64_t k = 0)
    {
        return (k >= lb && k <= ub);
    }

    Bounds &operator-=(size_t k)
    {
        if (k == 0)
            return *this;
        if (isUnknown() || isNonFat())
            return *this;
        if (k > (size_t)ub)
            ub = UNKNOWN_BOUND;
        else
            ub -= (int64_t)k;
        return *this;
    }

    static Bounds min(Bounds bounds1, Bounds bounds2)
    {
        return Bounds(0, std::min(bounds1.ub, bounds2.ub));
    }
};

typedef map<Value *, Bounds> BoundsInfo;

/*
 * Prototypes.
 */
static Bounds getPtrBounds(const TargetLibraryInfo *TLI, const DataLayout *DL,
    Value *Ptr, BoundsInfo &boundsInfo);
static Value *calcBasePtr(Function *F, Value *Ptr);
static Value *calcBasePtr(const TargetLibraryInfo *TLI, Function *F,
    Value *Ptr, PtrInfo &baseInfo);
static void getInterestingInsts(const TargetLibraryInfo *TL,
    const DataLayout *DL, BoundsInfo &boundsInfo, Instruction *I, Plan &plan);
static void insertBoundsCheck(const DataLayout *DL, Instruction *I, Value *Ptr,
    unsigned info, const PtrInfo &baseInfo);
static bool isInterestingAlloca(Instruction *I);
static bool isInterestingGlobal(GlobalVariable *GV);

/*
 * Options
 */
static cl::opt<bool> option_symbolize("lowfat-symbolize",
    cl::desc("Symbolizing constraints"));

static cl::opt<bool> option_debug("lowfat-debug",
    cl::desc("Dump before-and-after LowFat instrumented LLVM IR"));
static cl::opt<bool> option_no_check_reads("lowfat-no-check-reads",
    cl::desc("Do not OOB-check reads"));
static cl::opt<bool> option_no_check_writes("lowfat-no-check-writes",
    cl::desc("Do not OOB-check writes"));
static cl::opt<bool> option_no_check_escapes("lowfat-no-check-escapes",
    cl::desc("Do not OOB-check pointer escapes"));
static cl::opt<bool> option_no_check_memset("lowfat-no-check-memset",
    cl::desc("Do not OOB-check memset"));
static cl::opt<bool> option_no_check_memcpy("lowfat-no-check-memcpy",
    cl::desc("Do not OOB-check memcpy or memmove"));
static cl::opt<bool> option_no_check_escape_call("lowfat-no-check-escape-call",
    cl::desc("Do not OOB-check pointer call escapes"));
static cl::opt<bool> option_no_check_escape_return(
    "lowfat-no-check-escape-return",
    cl::desc("Do not OOB-check pointer return escapes"));
static cl::opt<bool> option_no_check_escape_store(
    "lowfat-no-check-escape-store",
    cl::desc("Do not OOB-check pointer store escapes"));
static cl::opt<bool> option_no_check_escape_ptr2int(
    "lowfat-no-check-escape-ptr2int",
    cl::desc("Do not OOB-check pointer pointer-to-int escapes"));
static cl::opt<bool> option_no_check_escape_insert(
    "lowfat-no-check-escape-insert",
    cl::desc("Do not OOB-check pointer vector insert escapes"));
static cl::opt<bool> option_no_check_fields(
    "lowfat-no-check-fields",
    cl::desc("Do not OOB-check field access (reduces the number of checks)"));
static cl::opt<bool> option_check_whole_access(
    "lowfat-check-whole-access",
    cl::desc("OOB-check the whole pointer access ptr..ptr+sizeof(*ptr) as "
        "opposed to just ptr (increases the number and cost of checks)"));
static cl::opt<bool> option_no_replace_malloc(
    "lowfat-no-replace-malloc",
    cl::desc("Do not replace malloc() with LowFat malloc() "
        "(disables heap protection)"));
static cl::opt<bool> option_no_replace_alloca(
    "lowfat-no-replace-alloca",
    cl::desc("Do not replace stack allocation (alloca) with LowFat stack "
        "allocation (disables stack protection)"));
static cl::opt<bool> option_no_replace_globals(
    "lowfat-no-replace-globals",
    cl::desc("Do not replace globals with LowFat globals "
        "(disables global variable protection; should also be combined with "
        "-mcmodel=small)"));
static cl::opt<string> option_no_check_blacklist(
    "lowfat-no-check-blacklist",
    cl::desc("Do not OOB-check the functions/modules specified in the "
        "given blacklist"),
    cl::init("-"));
static cl::opt<bool> option_no_abort(
    "lowfat-no-abort",
    cl::desc("Do not abort the program if an OOB memory error occurs"));

/*
 * Fool-proof "leading zero count" implementation.  Also works for "0".
 */
static size_t clzll(uint64_t x)
{
    if (x == 0)
        return 64;
    uint64_t bit = (uint64_t)1 << 63;
    size_t count = 0;
    while ((x & bit) == 0)
    {
        count++;
        bit >>= 1;
    }
    return count;
}

/*
 * Test if we should ignore instrumentation for this pointer.
 */
static bool filterPtr(unsigned kind)
{
    switch (kind)
    {
        case LOWFAT_OOB_ERROR_READ:
            return option_no_check_reads;
        case LOWFAT_OOB_ERROR_WRITE:
            return option_no_check_writes;
        case LOWFAT_OOB_ERROR_MEMSET:
            return option_no_check_memset;
        case LOWFAT_OOB_ERROR_MEMCPY:
            return option_no_check_memcpy;
        case LOWFAT_OOB_ERROR_ESCAPE_CALL:
            return option_no_check_escape_call || option_no_check_escapes;
        case LOWFAT_OOB_ERROR_ESCAPE_RETURN:
            return option_no_check_escape_return || option_no_check_escapes;
        case LOWFAT_OOB_ERROR_ESCAPE_STORE:
            return option_no_check_escape_store || option_no_check_escapes;
        case LOWFAT_OOB_ERROR_ESCAPE_PTR2INT:
            return option_no_check_escape_ptr2int || option_no_check_escapes;
        case LOWFAT_OOB_ERROR_ESCAPE_INSERT:
            return option_no_check_escape_insert || option_no_check_escapes;
        default:
            return false;
    }
}

/*
 * LowFat warning message class.
 */
class LowFatWarning : public DiagnosticInfo
{
    private:
        string msg;
    
    public:
        LowFatWarning(const char *msg) : DiagnosticInfo(777, DS_Warning),
            msg(msg) { }
        void print(DiagnosticPrinter &dp) const override;
};

void LowFatWarning::print(DiagnosticPrinter &dp) const
{
    dp << "[LowFat] Warning: " << msg << "\n";
}

/*
 * Find the best place to insert instructions *after* `Ptr' is defined.
 */
static pair<BasicBlock *, BasicBlock::iterator> nextInsertPoint(Function *F,
    Value *Ptr)
{
    if (InvokeInst *Invoke = dyn_cast<InvokeInst>(Ptr))
    {
        // This is a tricky case since we an invoke instruction is also a
        // terminator.  Instead we create a new BasicBlock to insert into.
        BasicBlock *fromBB = Invoke->getParent();
        BasicBlock *toBB = Invoke->getNormalDest();
        BasicBlock *newBB = SplitEdge(fromBB, toBB);
        return make_pair(newBB, newBB->begin());
    }
    else if (isa<Argument>(Ptr) || isa<GlobalValue>(Ptr))
    {
        // For arguments or globals we insert into the entry basic block.
        BasicBlock &Entry = F->getEntryBlock();
        return make_pair(&Entry, Entry.begin());
    }
    else if (isa<Instruction>(Ptr) && !isa<TerminatorInst>(Ptr))
    {
        Instruction *I = dyn_cast<Instruction>(Ptr);
        assert(I != nullptr);
        BasicBlock::iterator i(I);
        i++;
        BasicBlock *BB = I->getParent();
        return make_pair(BB, i);
    }
    else
    {
        Ptr->getContext().diagnose(LowFatWarning(
            "(BUG) failed to calculate insert point"));
        BasicBlock &Entry = F->getEntryBlock();
        return make_pair(&Entry, Entry.begin());
    }
}

/*
 * Replace:
 *     ptr = lowfat_malloc(size);
 * with
 *     ptr = lowfat_malloc_index(idx, size);
 * If `size' is a constant and therefore `idx' can be calculated statically.
 * This saves a few CPU cycles per malloc call.
 */
static void optimizeMalloc(Module *M, Instruction *I,
    vector<Instruction *> &dels)
{
    CallSite Call(I);
    if (!Call.isCall() && !Call.isInvoke())
        return;
    Function *F = Call.getCalledFunction();
    if (F == nullptr || !F->hasName())
        return;
    if (Call.getNumArgOperands() != 1)
        return;
    switch (Call.getNumArgOperands())
    {
        case 1:
            if (F->getName() != "lowfat_malloc" &&
                    F->getName() != "lowfat__Znwm" &&
                    F->getName() != "lowfat__Znam")
                return;
            break;
        case 2:
            if (F->getName() != "lowfat__ZnwmRKSt9nothrow_t" &&
                    F->getName() != "lowfat__ZnamRKSt9nothrow_t")
                return;
            break;
        default:
            return;
    }
    Value *Arg = Call.getArgOperand(0);
    ConstantInt *Size = dyn_cast<ConstantInt>(Arg);
    if (Size == nullptr)
    {
        // Malloc argument is not a constant; skip.
        return;
    }
    size_t size = Size->getValue().getZExtValue();
    size_t idx = lowfat_heap_select(size);

    IRBuilder<> builder(I);
    Constant *MallocIdx = M->getOrInsertFunction("lowfat_malloc_index",
        builder.getInt8PtrTy(), builder.getInt64Ty(), builder.getInt64Ty(),
        nullptr);
    ConstantInt *Idx = builder.getInt64(idx);
    Value *NewCall = nullptr;
    if (auto *Invoke = dyn_cast<InvokeInst>(I))
    {
        InvokeInst *NewInvoke = builder.CreateInvoke(MallocIdx,
            Invoke->getNormalDest(), Invoke->getUnwindDest(), {Idx, Size});
        NewInvoke->setDoesNotThrow();
        NewCall = NewInvoke;
    }
    else
        NewCall = builder.CreateCall(MallocIdx, {Idx, Size});
    I->replaceAllUsesWith(NewCall);
    dels.push_back(I);
}

/*
 * Test if the given pointer is a memory allocation.  If so, then we know
 * that is pointer is already a base-pointer, so no need to call
 * lowfat_base().
 * TODO: I had planed to use TLI for this, but appears not to work correctly.
 */
static bool isMemoryAllocation(const TargetLibraryInfo *TLI, Value *Ptr)
{
    if (option_no_replace_malloc)
        return false;
    Function *F = nullptr;
    if (CallInst *Call = dyn_cast<CallInst>(Ptr))
        F = Call->getCalledFunction();
    else if (InvokeInst *Invoke = dyn_cast<InvokeInst>(Ptr))
        F = Invoke->getCalledFunction();
    else
        return false;
    if (F == nullptr)
        return false;
    if (!F->hasName())
        return false;
    const string &Name = F->getName().str();
    if (Name == "malloc" || Name == "realloc" || Name == "_Znwm" ||
            Name == "_Znam" || Name == "_ZnwmRKSt9nothrow_t" ||
            Name == "_ZnamRKSt9nothrow_t" || Name == "calloc" ||
            Name == "valloc" || Name == "strdup" || Name == "strndup")
        return true;
    return false;
}

/*
 * Get the (assumed) bounds of input pointers.  By default this is the "empty"
 * bounds, meaning that the pointer is assumed to be within bounds, but any
 * pointer arithmetic is assumed to be possibly-OOB.
 *
 * If `option_no_check_fields` is set, then offsets [0..sizeof(*ptr)] will be
 * assumed to be within bounds, effectively meaning that fields are never
 * bounds checked.  (This emulates the behavior of some other bounds checkers
 * like BaggyBounds and PAriCheck).
 */
static Bounds getInputPtrBounds(const DataLayout *DL, Value *Ptr)
{
    if (!option_no_check_fields)
        return Bounds::empty();
    Type *Ty = Ptr->getType();
    PointerType *PtrTy = dyn_cast<PointerType>(Ty);
    if (PtrTy == nullptr)
        return Bounds::empty();
    Ty = PtrTy->getElementType();
    if (!Ty->isSized())
        return Bounds::empty();
    size_t size = DL->getTypeAllocSize(Ty);
    return Bounds(0, size);
}

/*
 * Get the size of a constant object.  This is very similar to getPtrBounds()
 * defined below.
 */
static Bounds getConstantPtrBounds(const TargetLibraryInfo *TLI,
    const DataLayout *DL, Constant *C, BoundsInfo &boundsInfo)
{
    if (isa<ConstantPointerNull>(C))
        return Bounds::nonFat();
    else if (isa<UndefValue>(C))
        return Bounds::nonFat();

    auto i = boundsInfo.find(C);
    if (i != boundsInfo.end())
        return i->second;

    Bounds bounds = Bounds::nonFat();
    if (GlobalVariable *GV = dyn_cast<GlobalVariable>(C))
    {
        Type *Ty = GV->getType();
        PointerType *PtrTy = dyn_cast<PointerType>(Ty);
        assert(PtrTy != nullptr);
        Ty = PtrTy->getElementType();
        size_t size = DL->getTypeAllocSize(Ty);
        if (size != 0)
        {
            // (size==0) implies unspecified size, e.g. int x[];
            bounds = Bounds(0, size);
        }
    }
    else if (ConstantExpr *CE = dyn_cast<ConstantExpr>(C))
    {
        switch (CE->getOpcode())
        {
            case Instruction::GetElementPtr:
            {
                GEPOperator *GEP = cast<GEPOperator>(CE);
                assert(GEP != nullptr);
                bounds = getPtrBounds(TLI, DL, GEP->getPointerOperand(),
                    boundsInfo);
                if (!bounds.isUnknown() && !bounds.isNonFat())
                {
                    APInt offset(64, 0);
                    if (GEP->accumulateConstantOffset(*DL, offset) &&
                            offset.isNonNegative())
                        bounds -= offset.getZExtValue();
                    else
                        bounds = Bounds::unknown();
                }
                break;
            }
            case Instruction::BitCast:
                bounds = getConstantPtrBounds(TLI, DL, CE->getOperand(0),
                    boundsInfo);
                break;
            case Instruction::Select:
            {
                Bounds bounds1 = getConstantPtrBounds(TLI, DL,
                    CE->getOperand(1), boundsInfo);
                Bounds bounds2 = getConstantPtrBounds(TLI, DL,
                    CE->getOperand(2), boundsInfo);
                bounds = Bounds::min(bounds1, bounds2);
                break;
            }
            case Instruction::IntToPtr:
            case Instruction::ExtractElement:
            case Instruction::ExtractValue:
                // Assumed to be non-fat pointers:
                bounds = Bounds::nonFat();
                break;
            default:
            {
                C->dump();
                C->getContext().diagnose(LowFatWarning(
                    "(BUG) unknown constant expression pointer type (size)"));
                break;
            }
        }
    }
    else if (isa<GlobalValue>(C))
        bounds = Bounds::nonFat();
    else
    {
        C->dump();
        C->getContext().diagnose(LowFatWarning(
            "(BUG) unknown constant pointer type (size)"));
    }

    boundsInfo.insert(make_pair(C, bounds));
    return bounds;
}

/*
 * Analysis that attempts to statically determine the (approx.) bounds of the
 * given object pointed to by `Ptr'.
 *
 * boundsInfo: a cache map for ptr's bounds
 */
static Bounds getPtrBounds(const TargetLibraryInfo *TLI, const DataLayout *DL,
    Value *Ptr, BoundsInfo &boundsInfo)
{
    auto i = boundsInfo.find(Ptr);
    if (i != boundsInfo.end())
        return i->second;

    Bounds bounds = Bounds::nonFat();
    if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(Ptr))
    {
        bounds = getPtrBounds(TLI, DL, GEP->getPointerOperand(), boundsInfo);
        if (!bounds.isUnknown() && !bounds.isNonFat())
        {
            APInt offset(64, 0);
            if (GEP->accumulateConstantOffset(*DL, offset) &&
                    offset.isNonNegative())
                bounds -= offset.getZExtValue();
            else
                bounds = Bounds::unknown();
        }
    }
    else if (AllocaInst *Alloca = dyn_cast<AllocaInst>(Ptr))
    {
        const Value *Size = Alloca->getArraySize();
        if (isa<ConstantInt>(Size) && Alloca->getAllocatedType()->isSized())
            bounds = Bounds(0, dyn_cast<ConstantInt>(Size)->getZExtValue() *
                DL->getTypeAllocSize(Alloca->getAllocatedType()));
        else
            bounds = getInputPtrBounds(DL, Ptr);
    }
    else if (BitCastInst *Cast = dyn_cast<BitCastInst>(Ptr))
        bounds = getPtrBounds(TLI, DL, Cast->getOperand(0), boundsInfo);
    else if (SelectInst *Select = dyn_cast<SelectInst>(Ptr))
    {
        Bounds bounds1 = getPtrBounds(TLI, DL, Select->getOperand(1),
            boundsInfo);
        Bounds bounds2 = getPtrBounds(TLI, DL, Select->getOperand(2),
            boundsInfo);
        bounds = Bounds::min(bounds1, bounds2);
    }
    else if (Constant *C = dyn_cast<Constant>(Ptr))
        bounds = getConstantPtrBounds(TLI, DL, C, boundsInfo);
    else if (isa<ConstantPointerNull>(Ptr) ||
             isa<GlobalValue>(Ptr) ||
             isa<UndefValue>(Ptr))                  // Treat as non-fat
        bounds = Bounds::nonFat();
    else if (isa<IntToPtrInst>(Ptr) ||
                isa<Argument>(Ptr) ||
                isa<LoadInst>(Ptr) ||
                isa<ExtractValueInst>(Ptr) ||
                isa<ExtractElementInst>(Ptr))
        bounds = getInputPtrBounds(DL, Ptr);        // Input pointers.
    else if (isa<CallInst>(Ptr) || isa<InvokeInst>(Ptr))
    {
        uint64_t size;
        if (isMemoryAllocation(TLI, Ptr) && getObjectSize(Ptr, size, *DL, TLI))
            bounds = Bounds(0, size);
        else
            bounds = getInputPtrBounds(DL, Ptr);    // Input pointer (default).
    }
    else if (PHINode *PHI = dyn_cast<PHINode>(Ptr))
    {
        size_t numValues = PHI->getNumIncomingValues();
        bounds = Bounds::nonFat();
        boundsInfo.insert(make_pair(Ptr, Bounds::unknown()));
        for (size_t i = 0; i < numValues; i++)
        {
            Bounds boundsIn = getPtrBounds(TLI, DL, PHI->getIncomingValue(i),
                boundsInfo);
            bounds = Bounds::min(bounds, boundsIn);
            if (bounds.isUnknown())
                break;      // No point continuing.
        }
        boundsInfo.erase(Ptr);
    }
    else
    {
        Ptr->dump();
        Ptr->getContext().diagnose(LowFatWarning(
                    "(BUG) unknown pointer type (size)"));
    }

    boundsInfo.insert(make_pair(Ptr, bounds));
    return bounds;
}

/*
 * Insert an explicit lowfat_base(Ptr) operation after Ptr's origin.
 */
static Value *calcBasePtr(Function *F, Value *Ptr)
{

#if(defined LOWFAT_REVERSE_MEM_LAYOUT && defined LOWFAT_MEMCPY_CHECK)
//#ifdef LOWFAT_REVERSE_MEM_LAYOUT
    auto i = nextInsertPoint(F, Ptr);
    IRBuilder<> builder(i.first, i.second);
    Ptr = builder.CreateBitCast(Ptr, builder.getInt8PtrTy());
    return Ptr;
#else

    auto i = nextInsertPoint(F, Ptr);
    IRBuilder<> builder(i.first, i.second);
    Module *M = F->getParent();
    Value *G = M->getOrInsertFunction("lowfat_base",
        builder.getInt8PtrTy(), builder.getInt8PtrTy(), nullptr);
    Ptr = builder.CreateBitCast(Ptr, builder.getInt8PtrTy());
    Value *BasePtr = builder.CreateCall(G, {Ptr});
    return BasePtr;
#endif
}

/*
 * Calculate the base pointer of a constant.
 */
static Constant *calcBasePtr(const TargetLibraryInfo *TLI, Function *F,
    Constant *C, PtrInfo &baseInfo)
{
    if (option_no_replace_globals)
        return ConstantPointerNull::get(Type::getInt8PtrTy(C->getContext()));

    ConstantExpr *CE = dyn_cast<ConstantExpr>(C);
    if (CE == nullptr)
        return ConstantExpr::getPointerCast(C,
            Type::getInt8PtrTy(C->getContext()));

    auto i = baseInfo.find(C);
    if (i != baseInfo.end())
    {
        Constant *R = dyn_cast<Constant>(i->second);
        assert(R != nullptr);
        return R;
    }

    Constant *BasePtr = nullptr;
    switch (CE->getOpcode())
    {
        case Instruction::GetElementPtr:
        {
            GEPOperator *GEP = cast<GEPOperator>(CE);
            assert(GEP != nullptr);
            Value *Ptr = GEP->getPointerOperand();
            Constant *CPtr = dyn_cast<Constant>(Ptr);
            assert(CPtr != nullptr);
            BasePtr = calcBasePtr(TLI, F, CPtr, baseInfo);
            break;
        }
        case Instruction::BitCast:
            BasePtr = calcBasePtr(TLI, F, CE->getOperand(0), baseInfo);
            break;
        case Instruction::Select:
        {
            Constant *BasePtrA = calcBasePtr(TLI, F, CE->getOperand(1),
                baseInfo);
            Constant *BasePtrB = calcBasePtr(TLI, F, CE->getOperand(2),
                baseInfo);
            BasePtr = ConstantExpr::getSelect(CE->getOperand(0), BasePtrA,
                BasePtrB);
            break;
        }
        case Instruction::IntToPtr:
        case Instruction::ExtractElement:
        case Instruction::ExtractValue:
            // Assumed to be non-fat pointers:
            BasePtr = 
                ConstantPointerNull::get(Type::getInt8PtrTy(CE->getContext()));
            break;
        default:
        {
            C->dump();
            C->getContext().diagnose(LowFatWarning(
                "(BUG) unknown constant expression pointer type (base)"));
            BasePtr = 
                ConstantPointerNull::get(Type::getInt8PtrTy(CE->getContext()));
            break;
        }
    }

    baseInfo.insert(make_pair(C, BasePtr));
    return BasePtr;
}

/*
 * Calculates the base pointer of an object.  The base pointer of `ptr' is:
 * - NULL if ptr==NULL or other non-fat pointer.
 * - ptr if ptr is the result of an allocation (e.g. malloc() or alloca())
 * - lowfat_base(ptr) otherwise.
 * See Figure 2 from "Heap Bounds Protection with Low Fat Pointers", except:
 * - Size is no longer propagated explicitly (instead we re-calculate from the
 *   base); and
 * - We also handle stack and global objects.
 */
static Value *calcBasePtr(const TargetLibraryInfo *TLI, Function *F,
    Value *Ptr, PtrInfo &baseInfo)
{
    auto i = baseInfo.find(Ptr);
    if (i != baseInfo.end()){

        return i->second;
    }

    Value *BasePtr = ConstantPointerNull::get(Type::getInt8PtrTy(Ptr->getContext()));

    if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(Ptr)) {
        BasePtr = calcBasePtr(TLI, F, GEP->getPointerOperand(), baseInfo);
    } else if (AllocaInst *Alloca = dyn_cast<AllocaInst>(Ptr)) {
        if (isInterestingAlloca(Alloca)) {
            auto i = nextInsertPoint(F, Ptr);
            IRBuilder<> builder(i.first, i.second);
            BasePtr = builder.CreateBitCast(Ptr, builder.getInt8PtrTy());
        }

    } else if (BitCastInst *Cast = dyn_cast<BitCastInst>(Ptr)) {
        BasePtr = calcBasePtr(TLI, F, Cast->getOperand(0), baseInfo);
    } else if (SelectInst *Select = dyn_cast<SelectInst>(Ptr)) {
        Value *BasePtrA = calcBasePtr(TLI, F, Select->getOperand(1),
            baseInfo);
        Value *BasePtrB = calcBasePtr(TLI, F, Select->getOperand(2),
            baseInfo);
        IRBuilder<> builder(Select);
        BasePtr = builder.CreateSelect(Select->getOperand(0), BasePtrA, BasePtrB);
    } else if (Constant *C = dyn_cast<Constant>(Ptr)) {

        BasePtr = calcBasePtr(TLI, F, C, baseInfo);

    } else if (isa<IntToPtrInst>(Ptr) ||
                isa<Argument>(Ptr) ||
                isa<LoadInst>(Ptr) ||
                isa<ExtractValueInst>(Ptr) ||
                isa<ExtractElementInst>(Ptr)){

        //TODO
        BasePtr = calcBasePtr(F, Ptr);

    } else if (isa<CallInst>(Ptr) || isa<InvokeInst>(Ptr)) {

        if (isMemoryAllocation(TLI, Ptr)) {
            auto i = nextInsertPoint(F, Ptr);
            IRBuilder<> builder(i.first, i.second);
            BasePtr = builder.CreateBitCast(Ptr, builder.getInt8PtrTy());
        } else {
            BasePtr = calcBasePtr(F, Ptr);
        }

    } else if (PHINode *PHI = dyn_cast<PHINode>(Ptr)) {

        size_t numValues = PHI->getNumIncomingValues();
        IRBuilder<> builder(PHI);
        PHINode *BasePHI = builder.CreatePHI(builder.getInt8PtrTy(),
            numValues);
        baseInfo.insert(make_pair(Ptr, BasePHI));
        for (size_t i = 0; i < numValues; i++) {
            BasePHI->addIncoming(UndefValue::get(builder.getInt8PtrTy()), PHI->getIncomingBlock(i));
        }
        bool allNonFat = true;
        for (size_t i = 0; i < numValues; i++) {
            Value *BasePtr = calcBasePtr(TLI, F, PHI->getIncomingValue(i), baseInfo);
            if (!isa<ConstantPointerNull>(BasePtr)){
                allNonFat = false;
            }
            BasePHI->setIncomingValue(i, BasePtr);
        }
        if (allNonFat) {
            // Cannot erase the PHI since it may exist in baseInfo.
            baseInfo.erase(Ptr);
            baseInfo.insert(make_pair(Ptr, BasePtr));
            return BasePtr;
        }

        return BasePHI;
    } else {
        Ptr->dump();
        Ptr->getContext().diagnose(LowFatWarning("(BUG) unknown pointer type (base)"));
        BasePtr = ConstantPointerNull::get(Type::getInt8PtrTy(Ptr->getContext()));
    }

    baseInfo.insert(make_pair(Ptr, BasePtr));
    return BasePtr;
}

/*
 * Test if an integer value escapes or not.  If it does not, then there is no
 * point bounds checking pointer->integer casts.
 */
static bool doesIntEscape(Value *Val, set<Value *> &seen)
{
    if (seen.find(Val) != seen.end())
        return false;
    seen.insert(Val);

    // Sanity check:
    if (Val->getType()->isVoidTy())
    {
        Val->dump();
        Val->getContext().diagnose(LowFatWarning(
            "(BUG) unknown integer escape"));
        return true;
    }

    for (User *User: Val->users())
    {
        if (isa<ReturnInst>(User) ||
                isa<CallInst>(User) ||
                isa<InvokeInst>(User) ||
                isa<StoreInst>(User) ||
                isa<IntToPtrInst>(User))
            return true;
        if (isa<CmpInst>(User) ||
                isa<BranchInst>(User) ||
                isa<SwitchInst>(User))
            continue;
        if (doesIntEscape(User, seen))
            return true;
    }

    return false;
}

/*
 * Test if a pointer is an "ugly GEP" or not.  Ugly GEPs can violate the
 * bounds assumptions and this leads to false OOB errors.  Note that this is
 * only a problem if the LowFat pass is inserted late in the optimization
 * pipeline.  TODO: find a better solution.
 */
static bool isUglyGEP(Value *Val)
{
    Instruction *I = dyn_cast<Instruction>(Val);
    if (I == nullptr)
        return false;
    if (I->getMetadata("uglygep") != NULL)
        return true;
    else
        return false;
}

/*
 * Accumulate (into `plan') all interesting instructions and the corresponding
 * pointer to check.  Here "interesting" means that the instruction should
 * be bounds checked.
 */
static void addToPlan(const TargetLibraryInfo *TLI, const DataLayout *DL,
    BoundsInfo &boundsInfo, Plan &plan, Instruction *I, Value *Ptr,
    unsigned kind)
{
    if (filterPtr(kind))
        return;
    Bounds bounds = getPtrBounds(TLI, DL, Ptr, boundsInfo);
    size_t size = 0;
    if (option_check_whole_access &&
            (kind == LOWFAT_OOB_ERROR_READ || kind == LOWFAT_OOB_ERROR_WRITE))
    {
        Type *Ty = Ptr->getType();
        if (auto *PtrTy = dyn_cast<PointerType>(Ty))
        {
            Ty = PtrTy->getElementType();
            size = DL->getTypeAllocSize(Ty);
        }
    }
    if (bounds.isInBounds(size))
        return;
    plan.push_back(make_tuple(I, Ptr, kind));   //tuple<Instruction *, Value *, unsigned>
}

static void getInterestingInsts(const TargetLibraryInfo *TLI,
    const DataLayout *DL, BoundsInfo &boundsInfo, Instruction *I, Plan &plan)
{
    if (I->getMetadata("nosanitize") != nullptr)
        return;
    Value *Ptr = nullptr;
    unsigned kind = LOWFAT_OOB_ERROR_UNKNOWN;
    if (StoreInst *Store = dyn_cast<StoreInst>(I))
    {
        Value *Val = Store->getValueOperand();
        if (Val->getType()->isPointerTy())
            addToPlan(TLI, DL, boundsInfo, plan, I, Val,
                LOWFAT_OOB_ERROR_ESCAPE_STORE);
        Ptr = Store->getPointerOperand();
        kind = LOWFAT_OOB_ERROR_WRITE;
    }
    else if (LoadInst *Load = dyn_cast<LoadInst>(I))
    {
        Ptr = Load->getPointerOperand();
        kind = LOWFAT_OOB_ERROR_READ;
    }
    else if (MemTransferInst *MI = dyn_cast<MemTransferInst>(I))
    {

        if (filterPtr(LOWFAT_OOB_ERROR_MEMCPY))
            return;
        IRBuilder<> builder(MI);
        Value *Src = builder.CreateBitCast(MI->getOperand(1),
            builder.getInt8PtrTy());

        Value* lastIndex = MI->getOperand(2);

#if(defined LOWFAT_REVERSE_MEM_LAYOUT && defined LOWFAT_MEMCPY_CHECK)
        if(ConstantInt* CI = dyn_cast<ConstantInt>(lastIndex)){
            APInt AI = CI->getValue();
            AI--;
            lastIndex = builder.getInt(AI);
        }else{
            lastIndex = builder.CreateSub(lastIndex, ConstantInt::get(lastIndex->getType(), 1, false));
        }
#endif

        //MI: <dest>, <src>, <len>, <isvolatile>
        Value *SrcEnd = builder.CreateGEP(Src,
            builder.CreateIntCast(lastIndex, builder.getInt64Ty(),
                false));

        addToPlan(TLI, DL, boundsInfo, plan, I, SrcEnd,
            LOWFAT_OOB_ERROR_MEMCPY);
        Value *Dst = builder.CreateBitCast(MI->getOperand(0),
            builder.getInt8PtrTy());
        Value *DstEnd = builder.CreateGEP(Dst,
            builder.CreateIntCast(lastIndex, builder.getInt64Ty(),
                false));

        addToPlan(TLI, DL, boundsInfo, plan, I, DstEnd,
            LOWFAT_OOB_ERROR_MEMCPY);
        return;
    }
    else if (MemSetInst *MI = dyn_cast<MemSetInst>(I))
    {
        if (filterPtr(LOWFAT_OOB_ERROR_MEMSET))
            return;
        IRBuilder<> builder(MI);
        Value *Dst = builder.CreateBitCast(MI->getOperand(0),
            builder.getInt8PtrTy());
        Value *DstEnd = builder.CreateGEP(Dst,
            builder.CreateIntCast(MI->getOperand(2), builder.getInt64Ty(),
                false));
        addToPlan(TLI, DL, boundsInfo, plan, I, DstEnd,
            LOWFAT_OOB_ERROR_MEMSET);
        return;
    }
    else if (PtrToIntInst *Ptr2Int = dyn_cast<PtrToIntInst>(I))
    {
        set<Value *> seen;
        if (!doesIntEscape(Ptr2Int, seen))
            return;
        Ptr = Ptr2Int->getPointerOperand();
        if (isUglyGEP(Ptr))
            return;
        kind = LOWFAT_OOB_ERROR_ESCAPE_PTR2INT;
    }
    else if (CallInst *Call = dyn_cast<CallInst>(I))
    {
        Function *F = Call->getCalledFunction();
        if (F != nullptr && F->doesNotAccessMemory())
            return;
        for (unsigned i = 0; i < Call->getNumArgOperands(); i++)
        {
            Value *Arg = Call->getArgOperand(i);
            if (Arg->getType()->isPointerTy())
                addToPlan(TLI, DL, boundsInfo, plan, I, Arg,
                    LOWFAT_OOB_ERROR_ESCAPE_CALL);
        }
        return;
    }
    else if (InvokeInst *Invoke = dyn_cast<InvokeInst>(I))
    {
        Function *F = Invoke->getCalledFunction();
        if (F != nullptr && F->doesNotAccessMemory())
            return;
        for (unsigned i = 0; i < Invoke->getNumArgOperands(); i++)
        {
            Value *Arg = Invoke->getArgOperand(i);
            if (Arg->getType()->isPointerTy())
                addToPlan(TLI, DL, boundsInfo, plan, I, Arg,
                    LOWFAT_OOB_ERROR_ESCAPE_CALL);
        }
        return;
    }
    else if (ReturnInst *Return = dyn_cast<ReturnInst>(I))
    {
        Ptr = Return->getReturnValue();
        if (Ptr == nullptr || !Ptr->getType()->isPointerTy())
            return;
        kind = LOWFAT_OOB_ERROR_ESCAPE_RETURN;
    }
    else if (InsertValueInst *Insert = dyn_cast<InsertValueInst>(I))
    {
        Ptr = Insert->getInsertedValueOperand();
        if (!Ptr->getType()->isPointerTy())
            return;
        kind = LOWFAT_OOB_ERROR_ESCAPE_INSERT;
    }
    else if (InsertElementInst *Insert = dyn_cast<InsertElementInst>(I))
    {
        Ptr = Insert->getOperand(1);
        if (!Ptr->getType()->isPointerTy())
            return;
        kind = LOWFAT_OOB_ERROR_ESCAPE_INSERT;
    }
    else if (AtomicRMWInst *Atomic = dyn_cast<AtomicRMWInst>(I))
    {
        Ptr = Atomic->getPointerOperand();
        kind = LOWFAT_OOB_ERROR_WRITE;
    }
    else if (AtomicCmpXchgInst *Atomic = dyn_cast<AtomicCmpXchgInst>(I))
    {
        Ptr = Atomic->getPointerOperand();
        kind = LOWFAT_OOB_ERROR_WRITE;
    }
    else
        return;

    addToPlan(TLI, DL, boundsInfo, plan, I, Ptr, kind); 
}

/*
 * Insert a bounds check before instruction `I'.
 */
static void insertBoundsCheck(const DataLayout *DL, Instruction *I, Value *Ptr,
    unsigned info, const PtrInfo &baseInfo)
{
    IRBuilder<> builder(I);
    auto i = baseInfo.find(Ptr);
    if (i == baseInfo.end())
    {
        missing_baseptr_error:
        Ptr->dump();
        Ptr->getContext().diagnose(LowFatWarning(
            "(BUG) missing base pointer"));
        return;
    }
    Value *BasePtr = i->second;
    if (BasePtr == nullptr)
        goto missing_baseptr_error;
    if (isa<ConstantPointerNull>(BasePtr))
    {
        // This is a nonfat pointer.
        return;
    }
    Module *M = builder.GetInsertBlock()->getParent()->getParent();
    size_t size = 0;
    if (option_check_whole_access &&
            (info == LOWFAT_OOB_ERROR_READ || info == LOWFAT_OOB_ERROR_WRITE))
    {
        Type *Ty = Ptr->getType();
        if (auto *PtrTy = dyn_cast<PointerType>(Ty))
        {
            Ty = PtrTy->getElementType();
            size = DL->getTypeAllocSize(Ty)-1;
        }
    }
    Value *Size = builder.getInt64(size);
    Ptr = builder.CreateBitCast(Ptr, builder.getInt8PtrTy());
    Value *BoundsCheck = M->getOrInsertFunction("lowfat_oob_check",
        builder.getVoidTy(), builder.getInt32Ty(), builder.getInt8PtrTy(),
        builder.getInt64Ty(), builder.getInt8PtrTy(), nullptr);

    builder.CreateCall(BoundsCheck, {builder.getInt32(info), Ptr, Size, BasePtr});
}

/*
 * Replace unsafe library functions.
 */
#include <malloc.h>

// STRING(1234) -> "1234"
#define STRING(a)   STRING2(a)
#define STRING2(a)  #a
#define REPLACE2(M, N, alloc)                                           \
    do {                                                                \
        if (Function *F0 = (M)->getFunction(N)) {                       \
            Value *F1 = (M)->getOrInsertFunction("lowfat_" N,           \
                F0->getFunctionType());                                 \
            F0->replaceAllUsesWith(F1);                                 \
            Function *F2 = dyn_cast<Function>(F1);                      \
            if ((alloc) && F2 != nullptr) {                             \
                F2->setDoesNotAlias(0);                                 \
                F2->setDoesNotThrow();                                  \
                F2->addAttribute(0, Attribute::NonNull);                \
            }                                                           \
        }                                                               \
    } while (false);
#define REPLACE(M, F, alloc)      REPLACE2(M, STRING(F), alloc)
static void replaceUnsafeLibFuncs(Module *M)
{
    REPLACE(M, memset, false);
    REPLACE(M, memcpy, false);
    REPLACE(M, memmove, false);

    if (option_no_replace_malloc)
        return;

    REPLACE(M, malloc, true);
    REPLACE(M, free, false);
    REPLACE(M, calloc, true);
    REPLACE(M, realloc, true);

    REPLACE(M, posix_memalign, false);
    REPLACE(M, aligned_alloc, true);
    REPLACE(M, valloc, true);
    REPLACE(M, memalign, true);
    REPLACE(M, pvalloc, true);

    REPLACE(M, strdup, true);
    REPLACE(M, strndup, true);

    REPLACE2(M, "_Znwm", true);                 // C++ new
    REPLACE2(M, "_Znam", true);                 // C++ new[]
    REPLACE2(M, "_ZdlPv", false);               // C++ delete
    REPLACE2(M, "_ZdaPv", false);               // C++ delete[]
    REPLACE2(M, "_ZnwmRKSt9nothrow_t", true);   // C++ new nothrow
    REPLACE2(M, "_ZnamRKSt9nothrow_t", true);   // C++ new[] nothrow
}

/*
 * Local definitions of LowFat functions.  See the corresponding definitions
 * from lowfat.c/lowfat.h for a human-readable C version.  Note that LowFat
 * options are only applied to the local definitions, and not the library
 * versions.
 */
static void addLowFatFuncs(Module *M)
{
    Function *F = M->getFunction("lowfat_base");
    if (F != nullptr)
    {
        BasicBlock *Entry = BasicBlock::Create(M->getContext(), "", F);
        IRBuilder<> builder(Entry);

        Value *Ptr = &F->getArgumentList().front();
        Value *Magics = builder.CreateIntToPtr(
            builder.getInt64((uint64_t)_LOWFAT_MAGICS),
            builder.getInt64Ty()->getPointerTo());
        Value *IPtr = builder.CreatePtrToInt(Ptr, builder.getInt64Ty());
        Value *Idx = builder.CreateLShr(IPtr,
            builder.getInt64(LOWFAT_REGION_SIZE_SHIFT));
        Value *MagicPtr = builder.CreateGEP(Magics, Idx);
        Value *Magic = builder.CreateAlignedLoad(MagicPtr, sizeof(size_t));
#if LOWFAT_IS_POW2
        Value *IBasePtr = builder.CreateAnd(IPtr, Magic);
#else
        Value *IPtr128 = builder.CreateZExt(IPtr, builder.getIntNTy(128));
        Value *Magic128 = builder.CreateZExt(Magic, builder.getIntNTy(128));
        Value *Tmp128 = builder.CreateMul(IPtr128, Magic128);
        Tmp128 = builder.CreateLShr(Tmp128, 64);
        Value *ObjIdx = builder.CreateTrunc(Tmp128, builder.getInt64Ty());
        Value *Sizes = builder.CreateIntToPtr(
            builder.getInt64((uint64_t)_LOWFAT_SIZES),
            builder.getInt64Ty()->getPointerTo());
        Value *SizePtr = builder.CreateGEP(Sizes, Idx);
        Value *Size = builder.CreateAlignedLoad(SizePtr, sizeof(size_t));
        Value *IBasePtr = builder.CreateMul(ObjIdx, Size);
#endif
        Value *BasePtr = builder.CreateIntToPtr(IBasePtr,
            builder.getInt8PtrTy());
        builder.CreateRet(BasePtr);
 
        F->setOnlyReadsMemory();
        F->setDoesNotThrow();
        F->setLinkage(GlobalValue::InternalLinkage);
        F->addFnAttr(llvm::Attribute::AlwaysInline);
    }

    /*
    F = M->getFunction("lowfat_oob_check");
    if (F != nullptr)
    {
        BasicBlock *Entry  = BasicBlock::Create(M->getContext(), "", F);
        BasicBlock *Error  = BasicBlock::Create(M->getContext(), "", F);
        BasicBlock *Return = BasicBlock::Create(M->getContext(), "", F);
        
        IRBuilder<> builder(Entry);
        auto i = F->getArgumentList().begin();
        Value *Info = &(*(i++));
        Value *Ptr = &(*(i++));
        Value *AccessSize = &(*(i++));
        Value *BasePtr = &(*(i++));
        Value *IBasePtr = builder.CreatePtrToInt(BasePtr,
            builder.getInt64Ty());
        Value *Idx = builder.CreateLShr(IBasePtr,
            builder.getInt64(LOWFAT_REGION_SIZE_SHIFT));
        Value *Sizes = builder.CreateIntToPtr(
            builder.getInt64((uint64_t)_LOWFAT_SIZES),
            builder.getInt64Ty()->getPointerTo());
        Value *SizePtr = builder.CreateGEP(Sizes, Idx);
        Value *Size = builder.CreateAlignedLoad(SizePtr, sizeof(size_t));
        
        // The check is: if (ptr - base > size - sizeof(*ptr)) error();
        Value *IPtr = builder.CreatePtrToInt(Ptr, builder.getInt64Ty());
        Value *Diff = builder.CreateSub(IPtr, IBasePtr);
        Size = builder.CreateSub(Size, AccessSize);
        Value *Cmp = builder.CreateICmpUGE(Diff, Size);
        builder.CreateCondBr(Cmp, Error, Return);
        
        IRBuilder<> builder2(Error);
        if (!option_no_abort)
        {
            Value *Error = M->getOrInsertFunction("lowfat_oob_error",
                builder2.getVoidTy(), builder2.getInt32Ty(),
                builder2.getInt8PtrTy(), builder2.getInt8PtrTy(), nullptr);
            CallInst *Call = builder2.CreateCall(Error, {Info, Ptr, BasePtr});
            Call->setDoesNotReturn();
            builder2.CreateUnreachable();
        }
        else
        {
            Value *Warning = M->getOrInsertFunction("lowfat_oob_warning",
                builder2.getVoidTy(), builder2.getInt32Ty(),
                builder2.getInt8PtrTy(), builder2.getInt8PtrTy(), nullptr);
            builder2.CreateCall(Warning, {Info, Ptr, BasePtr});
            builder2.CreateRetVoid();
        }

        IRBuilder<> builder3(Return);
        builder3.CreateRetVoid();

        F->setDoesNotThrow();
        F->setLinkage(GlobalValue::InternalLinkage);
        F->addFnAttr(llvm::Attribute::AlwaysInline);
    }*/

    F = M->getFunction("lowfat_stack_allocsize");
    if (F != nullptr)
    {
        BasicBlock *Entry = BasicBlock::Create(M->getContext(), "", F);

        IRBuilder<> builder(Entry);
        Value *Idx = &F->getArgumentList().front();
        Value *Sizes = M->getOrInsertGlobal("lowfat_stack_sizes",
            ArrayType::get(builder.getInt64Ty(), 0));
        if (GlobalVariable *Global = dyn_cast<GlobalVariable>(Sizes))
            Global->setConstant(true);
        vector<Value *> Idxs;
        Idxs.push_back(builder.getInt64(0));
        Idxs.push_back(Idx);
        Value *SizePtr = builder.CreateGEP(Sizes, Idxs);
        Value *Size = builder.CreateAlignedLoad(SizePtr, sizeof(size_t));
        builder.CreateRet(Size);

        F->setOnlyReadsMemory();
        F->setDoesNotThrow();
        F->setLinkage(GlobalValue::InternalLinkage);
        F->addFnAttr(llvm::Attribute::AlwaysInline);
    }

    F = M->getFunction("lowfat_stack_offset");
    if (F != nullptr)
    {
        BasicBlock *Entry = BasicBlock::Create(M->getContext(), "", F);

        IRBuilder<> builder(Entry);
        Value *Idx = &F->getArgumentList().front();
        Value *Sizes = M->getOrInsertGlobal("lowfat_stack_offsets",
            ArrayType::get(builder.getInt64Ty(), 0));
        if (GlobalVariable *Global = dyn_cast<GlobalVariable>(Sizes))
            Global->setConstant(true);
        vector<Value *> Idxs;
        Idxs.push_back(builder.getInt64(0));
        Idxs.push_back(Idx);
        Value *OffsetPtr = builder.CreateGEP(Sizes, Idxs);
        Value *Offset = builder.CreateAlignedLoad(OffsetPtr, sizeof(ssize_t));
        builder.CreateRet(Offset);

        F->setOnlyReadsMemory();
        F->setDoesNotThrow();
        F->setLinkage(GlobalValue::InternalLinkage);
        F->addFnAttr(llvm::Attribute::AlwaysInline);
    }

    F = M->getFunction("lowfat_stack_align");
    if (F != nullptr)
    {
        BasicBlock *Entry = BasicBlock::Create(M->getContext(), "", F);

        IRBuilder<> builder(Entry);
        Value *Ptr = &F->getArgumentList().front();
        Value *Idx = &F->getArgumentList().back();
        Value *IPtr = builder.CreatePtrToInt(Ptr, builder.getInt64Ty());
        Value *Masks = M->getOrInsertGlobal("lowfat_stack_masks",
            ArrayType::get(builder.getInt64Ty(), 0));
        if (GlobalVariable *Global = dyn_cast<GlobalVariable>(Masks))
            Global->setConstant(true);
        vector<Value *> Idxs;
        Idxs.push_back(builder.getInt64(0));
        Idxs.push_back(Idx);
        Value *MaskPtr = builder.CreateGEP(Masks, Idxs);
        Value *Mask = builder.CreateAlignedLoad(MaskPtr, sizeof(ssize_t));
        IPtr = builder.CreateAnd(IPtr, Mask);
        Ptr = builder.CreateIntToPtr(IPtr, builder.getInt8PtrTy());
        builder.CreateRet(Ptr);

        F->setOnlyReadsMemory();
        F->setDoesNotThrow();
        F->setLinkage(GlobalValue::InternalLinkage);
        F->addFnAttr(llvm::Attribute::AlwaysInline);
    }

    F = M->getFunction("lowfat_stack_mirror");
    if (F != nullptr)
    {
        BasicBlock *Entry = BasicBlock::Create(M->getContext(), "", F);

        IRBuilder<> builder(Entry);
        Value *Ptr = &F->getArgumentList().front();
        Value *Offset = &F->getArgumentList().back();
        Ptr = builder.CreateGEP(Ptr, Offset);
        builder.CreateRet(Ptr);

        F->setOnlyReadsMemory();
        F->setDoesNotThrow();
        F->setLinkage(GlobalValue::InternalLinkage);
        F->addFnAttr(llvm::Attribute::AlwaysInline);
    }

}

/*
 * Determine if the given alloca escapes (including if it is used in a bounds
 * check).  If it escapes then the alloca needs to be made non-fat.
 */
static bool doesAllocaEscape(Value *Val, set<Value *> &seen)
{
    // add wb, for debug
    return true;

    if (seen.find(Val) != seen.end())
        return false;
    seen.insert(Val);

    // Sanity check:
    if (Val->getType()->isVoidTy())
    {
        Val->dump();
        Val->getContext().diagnose(LowFatWarning(
            "(BUG) unknown alloca escape"));
        return true;
    }

    for (User *User: Val->users())
    {
        if (isa<ReturnInst>(User))
        {
            // Return local variable = undefined; so does not count
            continue;
        }
        if (isa<LoadInst>(User) || isa<CmpInst>(User))
            continue;
        if (StoreInst *Store = dyn_cast<StoreInst>(User))
        {
            if (Store->getPointerOperand() == Val)
                continue;
            return true;
        }
        if (isa<PtrToIntInst>(User))
        {
            set<Value *> seen;
            if (doesIntEscape(User, seen))
            {
                return true;
            }
            continue;
        }
        if (CallInst *Call = dyn_cast<CallInst>(User))  // Includes OOB-check
        {
            Function *F = Call->getCalledFunction();
            if (F != nullptr && F->doesNotAccessMemory())
                continue;
            return true;
        }
        if (InvokeInst *Invoke = dyn_cast<InvokeInst>(User))
        {
            Function *F = Invoke->getCalledFunction();
            if (F != nullptr && F->doesNotAccessMemory())
                continue;
            return true;
        }
        if (isa<GetElementPtrInst>(User) ||
            isa<BitCastInst>(User) ||
            isa<SelectInst>(User) ||
            isa<PHINode>(User))
        {
            if (doesAllocaEscape(User, seen))
                return true;
            continue;
        }

        // Sanity check:
        User->dump();
        User->getContext().diagnose(LowFatWarning(
            "(BUG) unknown alloca user"));
        return true;
    }

    return false;
}

/*
 * Determine if the given alloca is "interesting" or not.
 */
static bool isInterestingAlloca(Instruction *I)
{
    if (option_no_replace_alloca)
        return false;
    AllocaInst *Alloca = dyn_cast<AllocaInst>(I);
    if (Alloca == nullptr)
        return false;
    set<Value *> seen;
    if (doesAllocaEscape(Alloca, seen)){
        return true;
    }

    return false;
}

/*
 * Determine if the given global variant is "interesting" or not.
 */
static bool isInterestingGlobal(GlobalVariable *GV)
{
    if (option_no_replace_globals)
        return false;
    if (GV->hasSection())           // User-declared section
        return false;
    if (GV->getAlignment() > 16)    // User-declared alignment
        return false;
    if (GV->isThreadLocal())        // TLS not supported
        return false;
    switch (GV->getLinkage())
    {
        case GlobalValue::ExternalLinkage:
        case GlobalValue::InternalLinkage:
        case GlobalValue::PrivateLinkage:
        case GlobalValue::WeakAnyLinkage:
        case GlobalValue::WeakODRLinkage:
        case GlobalValue::CommonLinkage:
            break;
        default:
            return false;               // No "fancy" linkage
    }
    return true;
}

/*
 * Convert a global variable into a low-fat-pointer.  This is simple:
 * - Set the global object to be allocSize-aligned; and
 * - Put the object in the low-fat section corresponding for allocSize.
 * The linker will ensure that the sections are placed in the correct low-fat
 * regions.
 */
static void makeGlobalVariableLowFatPtr(Module *M, GlobalVariable *GV)
{
    if (GV->isDeclaration())
        return;
    if (!isInterestingGlobal(GV))
        return;

    // If common linkage is used, then the linker will ignore the "section"
    // attribute and put the object in the .BSS section.  Note that doing this
    // may break some legacy code that depends on common symbols.
    if (GV->hasCommonLinkage())
        GV->setLinkage(llvm::GlobalValue::WeakAnyLinkage);
 
    const DataLayout *DL = &M->getDataLayout();
    Type *Ty = GV->getType();
    PointerType *PtrTy = dyn_cast<PointerType>(Ty);
    assert(PtrTy != nullptr);
    Ty = PtrTy->getElementType();
    size_t size = DL->getTypeAllocSize(Ty);
    size_t idx = clzll(size);
    if (idx <= clzll(LOWFAT_MAX_GLOBAL_ALLOC_SIZE))
    {
        GV->dump();
        GV->getContext().diagnose(LowFatWarning(
            "Global variable cannot be made low-fat (too big)"));
        return;
    }
    size_t align = ~lowfat_stack_masks[idx] + 1;
    if (align > GV->getAlignment())
        GV->setAlignment(align);

    size_t newSize = lowfat_stack_sizes[idx];
    string section("lowfat_section_");
    if (GV->isConstant())
        section += "const_";
    section += to_string(newSize);

    GV->setSection(section);
}

static pair<StructType*, StructType*> declear_global_types(Module* M);
static string get_value_name(Function* F, Value *param, map<Value *, string> &valueNameMap);
static map<Value*, string> collect_local_variable_metadata(Function& F);
static void initializeGlobalHead(Module* M, GlobalVariable *gvar_struct_head, string val_name, StructType * head_type, StructType * list_type);

/*
 * Convert an alloca instruction into a low-fat-pointer.  This is a more
 * complicated transformation described in the paper:
 * "Stack Bounds Protection with Low Fat Pointers", in NDSS 2017.
 */
static void makeAllocaLowFatPtr(Module *M, Instruction *I)
{

    AllocaInst *Alloca = dyn_cast<AllocaInst>(I);
    if (Alloca == nullptr)
        return;

    const DataLayout *DL = &M->getDataLayout();

    Value *Size = Alloca->getArraySize();

    Type *Ty = Alloca->getAllocatedType();
    ConstantInt *ISize = dyn_cast<ConstantInt>(Size);
    Function *F = I->getParent()->getParent();
    auto i = nextInsertPoint(F, Alloca);
    IRBuilder<> builder(i.first, i.second);
    Value *Idx = nullptr, *Offset = nullptr, *AllocedPtr = nullptr;
    Value *NoReplace1 = nullptr, *NoReplace2 = nullptr;
    Value *CastAlloca = nullptr;
    Value *LifetimeSize = nullptr;

    Value *RequiredSize = nullptr;
    Value *AllocatedSize = nullptr;

    bool delAlloca = false;

    bool fix_len = (ISize != nullptr);
    if (fix_len)
    {
        // Simple+common case: fixed sized alloca:
        size_t size = DL->getTypeAllocSize(Ty) * ISize->getZExtValue();

        RequiredSize = ConstantInt::get(builder.getInt64Ty(), size);

        // STEP (1): Align the stack:
        size_t idx = clzll(size);
        if (idx <= clzll(LOWFAT_MAX_STACK_ALLOC_SIZE))
        {
            Alloca->dump();
            Alloca->getContext().diagnose(LowFatWarning(
                "Stack allocation cannot be made low-fat (too big)"));
            return;
        }
        ssize_t offset = lowfat_stack_offsets[idx];
        size_t align = ~lowfat_stack_masks[idx] + 1;
        if (align > Alloca->getAlignment())
            Alloca->setAlignment(align);

        // STEP (2): Adjust the allocation size:
        size_t newSize = lowfat_stack_sizes[idx];
        if (newSize != size)
        {
            /*
             * LLVM doubles the allocSz when the object is allocSz-aligned for
             * some reason (gcc does not seem to do this).  This wastes space
             * but it does not seem there is anything we can do about it.
             */
            LifetimeSize = builder.getInt64(newSize);
            AllocaInst *NewAlloca = builder.CreateAlloca(
                builder.getInt8Ty(), LifetimeSize);
            NewAlloca->setAlignment(Alloca->getAlignment());
            AllocedPtr = NewAlloca;
            delAlloca = true;

            AllocatedSize = NewAlloca->getArraySize();
        }
        else{
            AllocedPtr = builder.CreateBitCast(Alloca, builder.getInt8PtrTy());
            AllocatedSize = RequiredSize;
        }
        Offset = builder.getInt64(offset);
        CastAlloca = AllocedPtr;
        NoReplace1 = AllocedPtr;
    }
    else
    {
#ifdef LOWFAT_LEGACY
        // VLAs are disabled for LEGACY mode due to the alloca(0) problem.
        return;
#else
        // Complex+hard case: variable length stack object (e.g. VLAs)
        delAlloca = true;

        // STEP (1): Get the index/offset:
        RequiredSize = builder.CreateMul(builder.getInt64(DL->getTypeAllocSize(Ty)), Size);
        Constant *C = M->getOrInsertFunction("llvm.ctlz.i64",
            builder.getInt64Ty(), builder.getInt64Ty(), builder.getInt1Ty(),
            nullptr);
        Idx = builder.CreateCall(C, {RequiredSize, builder.getInt1(true)});
        if (CallInst *Call = dyn_cast<CallInst>(Idx))
            Call->setTailCall(true);
        C = M->getOrInsertFunction("lowfat_stack_offset",
            builder.getInt64Ty(), builder.getInt64Ty(), nullptr);
        Offset = builder.CreateCall(C, {Idx});
        if (CallInst *Call = dyn_cast<CallInst>(Offset))
            Call->setTailCall(true);

        // STEP (2): Get the actual allocation size:
        C = M->getOrInsertFunction("lowfat_stack_allocsize",
            builder.getInt64Ty(), builder.getInt64Ty(), nullptr);

        AllocatedSize = builder.CreateCall(C, {Idx});
        if (CallInst *Call = dyn_cast<CallInst>(AllocatedSize))
            Call->setTailCall(true);

        // STEP (3): Create replacement alloca():
        CastAlloca = builder.CreateAlloca(builder.getInt8Ty(), AllocatedSize);
        Value *SP = CastAlloca;     // SP = Stack pointer

        // STEP (4): Align the stack:
        C = M->getOrInsertFunction("lowfat_stack_align",
            builder.getInt8PtrTy(), builder.getInt8PtrTy(),
            builder.getInt64Ty(), nullptr);
        SP = builder.CreateCall(C, {SP, Idx});
        NoReplace1 = SP;
        if (CallInst *Call = dyn_cast<CallInst>(SP))
            Call->setTailCall(true);

        // STEP (5): Save the adjusted stack pointer:
        C = M->getOrInsertFunction("llvm.stackrestore",
            builder.getVoidTy(), builder.getInt8PtrTy(), nullptr);
        Value *_ = builder.CreateCall(C, {SP});
        if (CallInst *Call = dyn_cast<CallInst>(_))
            Call->setTailCall(true);

        AllocedPtr = SP;
#endif
    }

    // STEP (3)/(6): Mirror the pointer into a low-fat region:
    Value *C = M->getOrInsertFunction("lowfat_stack_mirror",
                                      builder.getInt8PtrTy(), builder.getInt8PtrTy(), builder.getInt64Ty(),
                                      nullptr);
    Value *MirroredPtr = builder.CreateCall(C, {AllocedPtr, Offset});

#ifndef LOWFAT_REVERSE_MEM_LAYOUT
    NoReplace2 = MirroredPtr;
    Value *Ptr = builder.CreateBitCast(MirroredPtr, Alloca->getType());
#else
    Value *reveredFunc = M->getOrInsertFunction("lowfat_stack_reverse",
                                      builder.getInt8PtrTy(), builder.getInt8PtrTy(), builder.getInt64Ty(), builder.getInt64Ty(),
                                      nullptr);

    // the last two parameter of lowfat_stack_reverse must be i64
    if(IntegerType* type = dyn_cast<IntegerType>(RequiredSize->getType())){
        if(type->getBitWidth() > 64){
            RequiredSize = builder.CreateZExt(RequiredSize, builder.getInt64Ty());
        } else if (type->getBitWidth() < 64) {
            RequiredSize = builder.CreateTrunc(RequiredSize, builder.getInt64Ty());
        }
    }
    if(IntegerType* type = dyn_cast<IntegerType>(AllocatedSize->getType())){
        if(type->getBitWidth() > 64){
            AllocatedSize = builder.CreateZExt(AllocatedSize, builder.getInt64Ty());
        } else if (type->getBitWidth() < 64) {
            AllocatedSize = builder.CreateTrunc(AllocatedSize, builder.getInt64Ty());
        }
    }

    Value *reversedPtr = builder.CreateCall(reveredFunc, {MirroredPtr, RequiredSize, AllocatedSize});

    MirroredPtr = reversedPtr; // set mirrored to reversed

    NoReplace2 = MirroredPtr;
    Value *Ptr = builder.CreateBitCast(reversedPtr, Alloca->getType());
#endif

    /********* add by wb **************/
    if(option_symbolize && !fix_len){
        std::pair<StructType*, StructType*> struct_types = declear_global_types(M);
        StructType* head_type = struct_types.first;
        StructType* list_type = struct_types.second;

        std::map<Value*, string> valueNameMap = collect_local_variable_metadata(*F);
        string val_name = get_value_name(F, Alloca, valueNameMap);

        // global name
        static int global_counter = 0;
        string global_name = "LOWFAT_STACK_GLOBAL_" + F->getName().str() + "_" + std::to_string(global_counter);
        global_counter++;

        // insert global
        GlobalVariable *gvar_struct_head = new GlobalVariable(*M, head_type, false, GlobalValue::ExternalLinkage, 0, global_name);
        gvar_struct_head->setAlignment(8);
        initializeGlobalHead(M, gvar_struct_head, val_name, head_type, list_type);

        Function* insert_map_func = M->getFunction("lowfat_insert_map");
        if (!insert_map_func) {
            //void lowfat_insert_map(size_t size, void* result, MALLOC_LIST_HEAD* global_head)
            std::vector<Type*> params;
            params.push_back(IntegerType::get(M->getContext(), 64));
            params.push_back(PointerType::get(IntegerType::get(M->getContext(), 8), 0));
            params.push_back(PointerType::get(head_type, 0));
            FunctionType* func_tp = FunctionType::get(
                    Type::getVoidTy(M->getContext()),
                    params,
                    false);


            insert_map_func = Function::Create(func_tp, GlobalValue::ExternalLinkage, "lowfat_insert_map", M);
            insert_map_func->setCallingConv(CallingConv::C);
        }

        builder.CreateCall(insert_map_func, {RequiredSize, MirroredPtr, gvar_struct_head});

    }// end if(is_variable)
    /************ end *******************/


    // Replace all uses of `Alloca' with the (now low-fat) `Ptr'.
    // We do not replace lifetime intrinsics nor values used in the
    // construction of the low-fat pointer (NoReplace1, ...).
    vector<User *> replace, lifetimes;
    for (User *Usr: Alloca->users())
    {
        if (Usr == NoReplace1 || Usr == NoReplace2)
            continue;
        if (IntrinsicInst *Intr = dyn_cast<IntrinsicInst>(Usr))
        {
            if (Intr->getIntrinsicID() == Intrinsic::lifetime_start ||
                    Intr->getIntrinsicID() == Intrinsic::lifetime_end)
            {
                lifetimes.push_back(Usr);
                continue;
            }
        }
        if (BitCastInst *Cast = dyn_cast<BitCastInst>(Usr))
        {
            for (User *Usr2: Cast->users())
            {
                IntrinsicInst *Intr = dyn_cast<IntrinsicInst>(Usr2);
                if (Intr == nullptr)
                    continue;
                if (Intr->getIntrinsicID() == Intrinsic::lifetime_start ||
                        Intr->getIntrinsicID() == Intrinsic::lifetime_end)
                    lifetimes.push_back(Usr2);
            }
        }
        replace.push_back(Usr);
    }
    for (User *Usr: replace)
        Usr->replaceUsesOfWith(Alloca, Ptr);
    for (User *Usr: lifetimes)
    {
        // Lifetimes are deleted.  The alternative is to insert the mirroring
        // after the lifetime start, however, this proved too difficult to get
        // working.  One problem is intermediate casts which may be reused.
        if (auto *Lifetime = dyn_cast<Instruction>(Usr))
            Lifetime->eraseFromParent();
    }
    if (delAlloca)
        Alloca->eraseFromParent();
}

/*
 * Blacklist checking.
 */
static bool isBlacklisted(SpecialCaseList *SCL, Module *M)
{
    if (SCL == nullptr)
        return false;
    if (SCL->inSection("src", M->getModuleIdentifier()))
        return true;
    return false;
}
static bool isBlacklisted(SpecialCaseList *SCL, Function *F)
{
    if (SCL == nullptr)
        return false;
    return SCL->inSection("fun", F->getName());
}


static void initializeGlobalHead(Module* M, GlobalVariable *gvar_struct_head, string val_name, StructType * head_type, StructType * list_type){

    Constant *name = ConstantDataArray::getString(M->getContext(), val_name, true);

    // plus one for \0
    size_t len = val_name.length() + 1;

    Type* arr_type = ArrayType::get(IntegerType::get(M->getContext(), 8), len);
    GlobalVariable* gvar_name = new GlobalVariable(*M,
            arr_type,
            true,
            GlobalValue::PrivateLinkage,
            name,
            ".str");
    gvar_name->setAlignment(1);

    ConstantInt* zero = ConstantInt::get(M->getContext(), APInt(32, StringRef("0"), 10));

    std::vector<Constant*> indices;
    indices.push_back(zero);
    indices.push_back(zero);

    Constant* get_ele_ptr = ConstantExpr::getGetElementPtr(arr_type, gvar_name, indices);

    std::vector<Constant*> contents;
    contents.push_back(zero);
    contents.push_back(get_ele_ptr);
    contents.push_back(ConstantPointerNull::get(PointerType::get(list_type, 0)));

    Constant* const_head = ConstantStruct::get(head_type, contents);
    gvar_struct_head->setInitializer(const_head);

    //gvar_struct_head->dump();
}

static string get_value_name(Function* F, Value *param, map<Value *, string> &valueNameMap){

    int instCount = 0;
    for (BasicBlock& BB : *F) {
        instCount += std::distance(BB.begin(), BB.end());
    }

    int i = 0;

    //param->dump();
    llvm::errs()<<"\nBEGIN get_value_name >>>>> "<< F->getName() <<" >>>>>>>>>>>>>>>>>>>>>>>>>\n";
    //errs()<<param<<"\n";

    while(i < instCount){
        i++;

        //param->dump();

        if(valueNameMap.count(param)){

            //param->dump();
            errs()<<" === > "<<valueNameMap[param]<<"\n";

//            std::string type_str;
//            llvm::raw_string_ostream rso(type_str);
//            param->getType()->print(rso);

            return valueNameMap[param];

        } else {

            if(BitCastInst* bc = dyn_cast<BitCastInst>(param)){
                param = dyn_cast<Instruction>(bc->getOperand(0));
                continue;
            }
            if(AllocaInst* al = dyn_cast<AllocaInst>(param)){
                param = al->getArraySize();
                continue;
            }
        }
    }
    llvm::errs()<<"END >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n";

    static int counter = 0;

    string tmp_name = "tmp_" + F->getName().str() + "_" + std::to_string(counter);
    counter++;
    return tmp_name;
}

static std::map<Value*, string> collect_local_variable_metadata(Function& F){
    std::map<Value*, string> valueNameMap;

    for (auto &BB: F){
        for (auto &I: BB){
            if(DbgValueInst *llvm_dbg_value = dyn_cast<DbgValueInst>(&I)){
                if(MetadataAsValue* val = dyn_cast_or_null<MetadataAsValue>(llvm_dbg_value->getOperand(0))){
                    if(ValueAsMetadata* valueAsMetadata = dyn_cast<ValueAsMetadata>(val->getMetadata())){

                        //valueAsMetadata->getValue()->dump();
                        errs()<<"DUMPING META-INFO: "<<llvm_dbg_value->getVariable()->getRawName()->getString()<<"\n";

                        Value* key = valueAsMetadata->getValue();
                        if(key != nullptr){
                            valueNameMap[key] = llvm_dbg_value->getVariable()->getRawName()->getString();
                        }
                    }
                }
            }
        }// end for(I)
    }// end for(BB)

    return valueNameMap;
}

/**
 *
 * @param fname
 * @param idx
 * @param call
 * @param head_type
 * @param list_ptr_type
 */
static void process_lowfat_malloc(string glo_name,
        string val_name,
        CallInst *call,
        StructType * head_type,
        StructType * list_type,
        vector<Instruction *> &dels){

    StringRef global_name = StringRef(glo_name);

    //llvm::errs()<<"GLOBAL_NAME: "<<global_name<<"\n";

    // new global value for the malloc
    IRBuilder<> builder(call);

    Module* M = call->getModule();
    GlobalVariable *gvar_struct_head = new GlobalVariable(*M, head_type, false, GlobalValue::ExternalLinkage, 0, global_name);
    gvar_struct_head->setAlignment(8);

    initializeGlobalHead(M, gvar_struct_head, val_name, head_type, list_type);

    Function *symbolize_malloc_func = M->getFunction("lowfat_malloc_symbolize");
    if(symbolize_malloc_func == nullptr){

        std::vector<Type*> vec;
        vec.push_back(IntegerType::get(M->getContext(), 64));
        vec.push_back(PointerType::get(head_type, 0));

        FunctionType* func_type = FunctionType::get(
                PointerType::get(IntegerType::get(M->getContext(), 8), 0),
                vec,
                false);

        symbolize_malloc_func = Function::Create(func_type, GlobalValue::ExternalLinkage, "lowfat_malloc_symbolize", M);
        symbolize_malloc_func->setCallingConv(CallingConv::C);
    }

    Value* size_param = call->getArgOperand(0);

    Value *symbolize_call = builder.CreateCall(symbolize_malloc_func, {size_param, gvar_struct_head});

    call->replaceAllUsesWith(symbolize_call);
    dels.push_back(call);
}


static std::pair<StructType*, StructType*> declear_global_types(Module* M){

    std::vector<StructType *> types = M->getIdentifiedStructTypes();

    StructType* head_type = nullptr;
    StructType* list_type = nullptr;
    for(auto &StructTy: types){

        if(StructTy->getName().str() == "struct.malloc_linked_list"){
            list_type = StructTy;
        }else if(StructTy->getName().str() == "struct.malloc_linked_list_head"){
            head_type = StructTy;
        }
    }
    if(head_type == nullptr){
        head_type = StructType::create(M->getContext(), "struct.malloc_linked_list_head");
        std::vector<Type*> vec_list_head;
        vec_list_head.push_back(IntegerType::get(M->getContext(), sizeof(int)));
        vec_list_head.push_back(PointerType::get(IntegerType::get(M->getContext(), sizeof(char)), 0));

        if(list_type == nullptr){
            list_type  = StructType::create(M->getContext(), "struct.malloc_linked_list");
            std::vector<Type*> vec_list_type;
            vec_list_type.push_back(IntegerType::get(M->getContext(), sizeof(int)));
            vec_list_type.push_back(PointerType::get(list_type, 0));
            if (list_type->isOpaque()) {
                list_type->setBody(vec_list_type, false);
            }
        }
        vec_list_head.push_back(list_type);
        if (head_type->isOpaque()) {
            head_type->setBody(vec_list_head, false);
        }
    }

    pair <StructType*, StructType*> result;
    result.first = head_type;
    result.second = list_type;
    return result;
}

/**
 * Processing Symbolize
 */
static void symbolize(Module *M){

    std::pair<StructType*, StructType*> struct_types = declear_global_types(M);

    StructType* head_type = struct_types.first;
    StructType* list_type = struct_types.second;

    vector<Instruction *> dels;
    for(auto &F: *M){
        if (F.isDeclaration())
            continue;

        string fname = F.getName().str();
        int idx = 0;

        // map[varibale] = metadata
        std::map<Value*, string> valueNameMap = collect_local_variable_metadata(F);

        errs()<<"================== "<<F.getName()<<"\n";

        for (auto &BB: F){
            for (auto &I: BB){
                //errs()<<"\n\n  ======== "<<&I<<"\n";
                //I.dump();

                if(CallInst *call = dyn_cast<CallInst>(&I)){
                    Function *called = call->getCalledFunction();
                    if (called == nullptr || !called->hasName()){
                        continue;
                    }
                    const string &Name = called->getName().str();
                    // pick out lowfat_malloc
                    if(Name == "lowfat_malloc"){
                        Value* length_var = dyn_cast<Value>(call->getArgOperand(0));

                        if(length_var == nullptr){
                            errs()<<"NULL!!!!!\n";
                            call->getArgOperand(0)->dump();
                        }
                        length_var->dump();

                        string global_name = "LOWFAT_MALLOC_GLOBAL_" + fname + "_" + std::to_string(idx);

                        if(ConstantInt* constant = dyn_cast<ConstantInt>(length_var)){
                            // allocate memory constantly
                            string rawdata = std::to_string(*constant->getValue().getRawData());
                            string value_name = F.getName().str() + "_const_" + rawdata;

                            process_lowfat_malloc(global_name, value_name, call, head_type, list_type, dels);

                        }else if(GlobalValue* global =  dyn_cast<GlobalValue>(length_var)){
                            // allocate memory via a global

                        }else{

                            //errs()<<"~~~~~~~~~~~~~~\n";

                            // allocate by local
                            string value_name = get_value_name(&F, length_var, valueNameMap);

                            // TODO
                            process_lowfat_malloc(global_name, value_name, call, head_type, list_type, dels);
                        }



                    }
                }
            }
        }

    }

    for(auto &I: dels){
        I->eraseFromParent();
    }

}// end static void symbolize(Module *M)


static void memory_overlap_check(Module *M) {
    for(auto &F: *M){
        if (F.isDeclaration())
            continue;

        for (auto &BB: F){
            for (auto &I: BB) {
                if(MemTransferInst* memInst = dyn_cast<MemTransferInst>(&I)){
                    IRBuilder<> builder(memInst);
                    Value* overFunc = M->getOrInsertFunction("lowfat_stack_mem_overlap",
                                               builder.getVoidTy(),
                                               builder.getInt8PtrTy(),
                                               builder.getInt8PtrTy(),
                                               builder.getInt64Ty(), nullptr);

                    builder.CreateCall(overFunc, {memInst->getOperand(0), memInst->getOperand(1), memInst->getOperand(2)});
                }
            }
        }
    }
}

/*
 * LowFat LLVM Pass
 */
namespace
{

struct LowFat : public ModulePass
{
    static char ID;
    LowFat() : ModulePass(ID) { }

    virtual bool runOnModule(Module &M)
    {
        if (option_debug)
        {
            string outName(M.getName());
            outName += ".in.lowfat.ll";
            std::error_code errInfo;
            raw_fd_ostream out(outName.c_str(), errInfo, sys::fs::F_None);
            M.print(out, nullptr);
        }

        // Read the blacklist file (if it exists)
        unique_ptr<SpecialCaseList> Blacklist = nullptr;
        if (option_no_check_blacklist != "-")
        {
            vector<string> paths;
            paths.push_back(option_no_check_blacklist);
            string err;
            Blacklist = SpecialCaseList::create(paths, err);
        }
        if (isBlacklisted(Blacklist.get(), &M))
            return true;


        // PASS (1): Bounds instrumentation
        const TargetLibraryInfo &TLI =
            getAnalysis<TargetLibraryInfoWrapperPass>().getTLI();
        const DataLayout *DL = &M.getDataLayout();
        for (auto &F: M)
        {
            if (F.isDeclaration())
                continue;
            if (isBlacklisted(Blacklist.get(), &F))
                continue;

//            if(F.getName().str() == "xmalloc"){
//                continue;
//            }

            // STEP #1: Find all instructions that we need to instrument:
            Plan plan;  //Plan: vector<tuple<Instruction *, Value *, unsigned>>: <pointer, bound, kind>
            BoundsInfo boundsInfo;  //BoundsInfo: map<Value *, Bounds>
            for (auto &BB: F)
                for (auto &I: BB)
                    getInterestingInsts(&TLI, DL, boundsInfo, &I, plan);

            // STEP #2: Calculate the base pointers:
            PtrInfo baseInfo;   // PtrInfo: map<Value *, Value *>
            for (auto &p: plan){
                (void)calcBasePtr(&TLI, &F, get<1>(p), baseInfo);   // get<1>(p): bound value
            }

            // STEP #3: Add the bounds check:
            for (auto &p: plan){
                insertBoundsCheck(DL, get<0>(p), get<1>(p), get<2>(p), baseInfo);
            }
        }

        // PASS (1a) Stack object lowfatification
        for (auto &F: M)
        {
            if (F.isDeclaration())
                continue;

            // STEP #1: Find all interesting allocas:
            vector<Instruction *> allocas;
            for (auto &BB: F)
                for (auto &I: BB)
                    if (isInterestingAlloca(&I))
                        allocas.push_back(&I);

            // STEP #2: Mirror all interesting allocas:
            for (auto *I: allocas)
                makeAllocaLowFatPtr(&M, I);
        }

        // Pass (1b) Global Variable lowfatification
        if (!option_no_replace_globals)
            for (auto &GV: M.getGlobalList())
                makeGlobalVariableLowFatPtr(&M, &GV);

        // PASS (2): Replace unsafe library calls
        replaceUnsafeLibFuncs(&M);

        // PASS (3): Add function definitions
        addLowFatFuncs(&M);

        // PASS (4): Optimize lowfat_malloc() calls
        /*if(!option_symbolize){
            for (auto &F: M)
            {
                if (F.isDeclaration())
                    continue;
                vector<Instruction *> dels;
                for (auto &BB: F)
                    for (auto &I: BB)
                        optimizeMalloc(&M, &I, dels);
                for (auto &I: dels)
                    I->eraseFromParent();
            }
        }*/

        // added by wb
        if(option_symbolize){
            symbolize(&M);
        }

        #if(defined LOWFAT_REVERSE_MEM_LAYOUT && defined LOWFAT_MEMCPY_CHECK)
        memory_overlap_check(&M);
        #endif

        if (option_debug)
        {
            string outName(M.getName());
            outName += ".out.lowfat.ll";
            std::error_code errInfo;
            raw_fd_ostream out(outName.c_str(), errInfo, sys::fs::F_None);
            M.print(out, nullptr);

            string errs;
            raw_string_ostream rso(errs);
            if (verifyModule(M, &rso))
            {
                fprintf(stderr, "LowFat generated broken IR!\n");
                fprintf(stderr, "%s\n", errs.c_str());
                abort();
            }
        }

        return true;
    }

    /*
     * Analysis usage specification.
     */
    virtual void getAnalysisUsage(AnalysisUsage &AU) const
    {
        AU.addRequired<TargetLibraryInfoWrapperPass>();
    }
};

}

char LowFat::ID = 0;
namespace llvm
{
    ModulePass *createLowFatPass()
    {
        return new LowFat();
    }
}

/*
 * Boilerplate for LowFat.so loadable module.
 */
#ifdef LOWFAT_PLUGIN
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"

static RegisterPass<LowFat> X("lowfat", "LowFat pass");

static void register_pass(const PassManagerBuilder &PMB,
    legacy::PassManagerBase &PM)
{
    PM.add(new LowFat());
}

static RegisterStandardPasses RegisterPass(
    PassManagerBuilder::EP_LoopOptimizerEnd, register_pass);
#endif      /* LOWFAT_PLUGIN */

