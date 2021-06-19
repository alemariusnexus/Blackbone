#include "RemoteLocalHook.h"

#include "../Process.h"
#include "../../Asm/LDasm.h"

#include <cstdio>



// Must be enough to hold the displaced original code (instr_align(sizeof(1*jmp64))) plus the return jmp (sizeof(1*jmp64))
#define THUNK_MAX_SIZE 50



namespace blackbone
{

RemoteLocalHook::RemoteLocalHook( class Process& process )
    : _process( process )
{
}

RemoteLocalHook::~RemoteLocalHook()
{
	reset();
}

size_t RemoteLocalHook::GetDisplacedOriginalCode( ptr_t address, uint8_t* code )
{
	auto it = _hooks.find( address );
	if (it == _hooks.end())
		return 0;
	HookCtx& ctx = it->second;
	if (code)
		memcpy(code, ctx.origCode, ctx.origCodeSize);
	return ctx.origCodeSize;
}

bool RemoteLocalHook::isHooked( ptr_t address ) const
{
	auto it = _hooks.find( address );
	if (it == _hooks.end())
		return false;
	return it->second.hooked;
}

NTSTATUS RemoteLocalHook::PrepareHook( ptr_t address, size_t maxHookSize, eJumpStrategy jumpStrategy, const asmjit::X86GpReg& reg )
{
	HookCtx ctx;

	ctx.address = address;
	ctx.jumpStrategy = jumpStrategy;
	ctx.jumpRegister = &reg;

	auto pagesize = _process.core().native()->pageSize();
    auto size = Align( maxHookSize + THUNK_MAX_SIZE, pagesize );

    auto allocation = _process.memory().AllocateClosest( size, PAGE_EXECUTE_READWRITE, address );
    if (!allocation)
        return allocation.status;

    ctx.hookData = std::move( allocation.result() );

    ctx.thunkAddr = ctx.hookData.ptr() + maxHookSize;


    bool x64 = !_process.core().isWow64();

    ctx.hookJumpCodeSize = GenerateJump( ctx, ctx.hookJumpCode, ctx.hookData.ptr(), address, x64 );

    NTSTATUS status = CopyOldCode( ctx, x64 );
    if (!NT_SUCCESS( status )) {
    	ctx.hookData.Free();
		return status;
    }

    ctx.hooked = false;

    _hooks.emplace( address, std::move(ctx) );

    return STATUS_SUCCESS;
}

NTSTATUS RemoteLocalHook::SetHook( ptr_t address, asmjit::Assembler& hook, eJumpStrategy jumpStrategy, const asmjit::X86GpReg& reg )
{
	bool x64 = !_process.core().isWow64();
    auto& mem = _process.memory();

    NTSTATUS status = STATUS_SUCCESS;

    auto it = _hooks.find( address );

    if (it == _hooks.end()) {
    	status = PrepareHook(address, hook.getCodeSize(), jumpStrategy, reg);
    	if (!NT_SUCCESS( status )) {
    		return status;
    	}

    	it = _hooks.find( address );
    }

    HookCtx& ctx = it->second;

    uint8_t hookCode[256];
    uint8_t* heapHookCode = nullptr; // Only used if hook.getCodeSize() > sizeof(hookCode)

    if (hook.getCodeSize() > sizeof(hookCode)) {
    	heapHookCode = new uint8_t[hook.getCodeSize()];
    }

    hook.setBaseAddress( ctx.hookData.ptr() );
	hook.relocCode( heapHookCode ? heapHookCode : hookCode );

	uint8_t jmpBackCode[sizeof(ctx.hookJumpCode)];
	uint8_t jmpBackCodeSize;

	jmpBackCodeSize = GenerateJump( ctx, jmpBackCode, address + ctx.origCodeSize, ctx.hookData.ptr() + hook.getCodeSize() + ctx.origCodeSize, x64 );

	if (hook.getCodeSize() > (ctx.thunkAddr - ctx.hookData.ptr())) {
    	// Can happen if PrepareHook() was called manually with maxCodeSize < hook.getCodeSize().
		delete[] heapHookCode;
    	return STATUS_NO_MEMORY;
    }

    mem.Write( ctx.hookData.ptr(), hook.getCodeSize(), heapHookCode ? heapHookCode : hookCode );
	mem.Write( ctx.thunkAddr, ctx.origCodeSize, ctx.patchedOrigCode );
	mem.Write( ctx.thunkAddr + ctx.origCodeSize, jmpBackCodeSize, jmpBackCode );

	// Fill region between end of hook and start of thunk with nop. This region is normally empty, but can be non-empty
	// if PrepareHook() was called manually with maxCodeSize > hook.getCodeSize().
	for (ptr_t addr = ctx.hookData.ptr() + hook.getCodeSize() ; addr < ctx.thunkAddr ; addr++)
	{
		uint8_t nop = 0x90;
		mem.Write(addr, nop);
	}

	delete[] heapHookCode;

	DWORD flOld = 0;
	mem.Protect( address, ctx.hookJumpCodeSize, PAGE_EXECUTE_READWRITE, &flOld );
	status = mem.Write( address, ctx.hookJumpCodeSize, ctx.hookJumpCode );
	mem.Protect( address, ctx.hookJumpCodeSize, flOld );

	if (NT_SUCCESS( status ))
		ctx.hooked = true;

	return status;
}

NTSTATUS RemoteLocalHook::Restore( ptr_t address )
{
	auto it = _hooks.find( address );
	if (it == _hooks.end()) {
		return STATUS_INVALID_ADDRESS;
	}

	HookCtx& ctx = it->second;

    NTSTATUS status = STATUS_SUCCESS;

	if (ctx.hooked) {
		DWORD flOld = 0;
		_process.memory().Protect( ctx.address, ctx.hookJumpCodeSize, PAGE_EXECUTE_READWRITE, &flOld );
		status = _process.memory().Write( ctx.address, ctx.origCodeSize, ctx.origCode );
		_process.memory().Protect( ctx.address, ctx.hookJumpCodeSize, flOld );

		if (!NT_SUCCESS( status )) {
			return status;
		}
	}
	if (ctx.hookData.valid()) {
		ctx.hookData.Free();
		ctx.hookData = MemBlock();
	}

	_hooks.erase(it);

    return status;
}

NTSTATUS RemoteLocalHook::Detach( ptr_t address )
{
	auto it = _hooks.find( address );
	if (it == _hooks.end()) {
		return STATUS_INVALID_ADDRESS;
	}

	HookCtx& ctx = it->second;

	ctx.hookData.Release();

	_hooks.erase(it);

	return STATUS_SUCCESS;
}

void RemoteLocalHook::reset()
{
	while (!_hooks.empty()) {
		Restore( _hooks.begin()->first );
	}
}

NTSTATUS RemoteLocalHook::CopyOldCode( HookCtx& ctx, bool x64 )
{
	NTSTATUS status = STATUS_SUCCESS;

	_process.memory().Read( ctx.address, sizeof( ctx.origCode ), ctx.origCode );
	memcpy( ctx.patchedOrigCode, ctx.origCode, sizeof(ctx.patchedOrigCode) );

    // Store original bytes
	uint8_t* src = ctx.origCode;
	ptr_t newAddr = ctx.thunkAddr;
    uint32_t thunkSize = 0;
    ldasm_data ld = { 0 };

    const int64_t diffMinVals[] = {0ll, -128ll, -32768ll, -8388608ll, -2147483648ll, -549755813888ll, -140737488355328ll, -36028797018963968ll, -9223372036854775807ll};
    const int64_t diffMaxVals[] = {0ll, 127ll, 32767ll, 8388607ll, 2147483647ll, 549755813887ll, 140737488355327ll, 36028797018963967ll, 9223372036854775807ll};

    do
    {
        uint32_t len = ldasm( src, &ld, x64 );

        // Determine code end
        if (ld.flags & F_INVALID
            || (len == 1 && (src[ld.opcd_offset] == 0xCC || src[ld.opcd_offset] == 0xC3))
            || (len == 3 && src[ld.opcd_offset] == 0xC2)
            || len + thunkSize > 128)
        {
            break;
        }

        // if instruction has relative offset, calculate new offset 
        if (ld.flags & F_RELATIVE)
        {
        	int32_t diff = 0;
            const uintptr_t ofst = (ld.disp_offset != 0 ? ld.disp_offset : ld.imm_offset);
            const uintptr_t sz = ld.disp_size != 0 ? ld.disp_size : ld.imm_size;

            memcpy( &diff, src + ofst, sz );

            // An attempted (partial) solution to https://github.com/DarthTon/Blackbone/issues/418
            // TODO: Do NOT adjust the offset if it points to WITHIN the code that's being moved!

            int64_t newDiff = ((int64_t) diff) + (((ptr_t) (ctx.address+thunkSize))-newAddr);

            if (newDiff < diffMinVals[sz]  ||  newDiff > diffMaxVals[sz]) {
            	status = STATUS_NOT_IMPLEMENTED;
            	break;
            }

            memcpy(ctx.patchedOrigCode + thunkSize + ofst, &newDiff, sz);
        }

        src += len;
        newAddr += len;
        thunkSize += len;
    } while (thunkSize < ctx.hookJumpCodeSize);

    assert(thunkSize <= MaxOriginalCodeLen);

    if (thunkSize < ctx.hookJumpCodeSize)
    {
    	// TODO: Anything else we can do now?
    }
    else
    {
    	ctx.origCodeSize = static_cast<uint8_t>(thunkSize);
    }

    return status;
}

uint8_t RemoteLocalHook::GenerateJump( HookCtx& ctx, uint8_t* code, ptr_t toAddr, ptr_t fromAddr, bool x64 ) const
{
	size_t size = 0;

	auto asmp = AsmFactory::GetAssembler();
	auto& a = *asmp;

	int64_t relJmp = toAddr >= fromAddr ? (int64_t) (toAddr-fromAddr) : -(int64_t)(fromAddr-toAddr);

	if (x64  &&  _abs64( relJmp ) > INT32_MAX)
	{
		switch (ctx.jumpStrategy)
		{
		case JumpPushMovRet:
			// A relatively non-intrusive way to jmp far on x86_64, leaving all registers intact.
			// As described on Nikolay Igotti's blog:
			//		https://web.archive.org/web/20090504135800/http://blogs.sun.com/nike/entry/long_absolute_jumps_on_amd64
			// See also Gil Dabah's blog post, where it's #3:
			//		https://www.ragestorm.net/blogs/?p=107

			// push toAddr[0:31]
			*code = 0x68;
			*((uint32_t*) (code+1)) = (uint32_t) (toAddr & 0xFFFFFFFF);

			if ((toAddr >> 32) != 0)
			{
				// mov [rsp+4], toAddr[32:63]
				*((uint32_t*) (code+5)) = 0x042444C7;
				*((uint32_t*) (code+9)) = (uint32_t) (toAddr >> 32);

				// ret
				*(code+13) = 0xC3;

				size = 14;
			}
			else
			{
				// ret
				*(code+5) = 0xC3;
				size = 6;
			}
			break;
		case JumpMovRegRet:
			// Alternative method that overwrites a register, but keeps the stack untouched. See #2:
			//		https://www.ragestorm.net/blogs/?p=107
			a->mov(*ctx.jumpRegister, (uint64_t) toAddr);
			a->jmp(*ctx.jumpRegister);
			size = uint8_t(a->relocCode(code));
			break;
		default:
			assert(false);
		}
	}
	else
	{
		// jmp rel toAddr
		*code = 0xE9;
		*((int32_t*) (code+1)) = (int32_t) (relJmp - 5);

		size = 5;
	}

	assert(size <= sizeof(ctx.hookJumpCode));
	return static_cast<uint8_t>(size);
}

}
