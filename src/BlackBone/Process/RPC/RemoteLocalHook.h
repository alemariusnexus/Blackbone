#pragma once

#include "../../Config.h"
#include "../../Asm/AsmFactory.h"
#include "../../Include/Types.h"
#include "../MemBlock.h"

#include <map>



namespace blackbone
{


/// <summary>
/// In-process remote hook
/// </summary>
class RemoteLocalHook
{
public:
	// Must be large enough to hold ANY jump this code uses
	static const size_t MaxHookJumpCodeLen = 14;

	// The displaced code should be at most 1 hook length + 1 instruction - 1 byte (if the hook jump overlaps with only the
	// first byte of the following instruction), and x86_64 instructions can be at most 15 bytes.
	static const size_t MaxOriginalCodeLen = MaxHookJumpCodeLen + 14;

	static const size_t MaxPatchedOriginalCodeLen = MaxOriginalCodeLen;

	enum eJumpStrategy
	{
		JumpPushMovRet,
		JumpMovRegRet
	};

private:
	/// <summary>
	/// Hook data
	/// </summary>
	#pragma pack(push, 1)
	struct HookCtx
	{
		ptr_t address; // Hooked address in original code
		ptr_t thunkAddr;
		uint8_t origCodeSize; // Size of displaced original code
		uint8_t origCode[MaxOriginalCodeLen]; // Copy of displaced original code
		uint8_t patchedOrigCode[MaxPatchedOriginalCodeLen];
		uint8_t hookJumpCode[MaxHookJumpCodeLen];
		uint8_t hookJumpCodeSize;

		MemBlock hookData;
		eJumpStrategy jumpStrategy;
		const asmjit::X86GpReg* jumpRegister;
		bool hooked;
	};
	#pragma pack(pop)

public:
    RemoteLocalHook( class Process& process );
    ~RemoteLocalHook();

    NTSTATUS SetHook( ptr_t address, asmjit::Assembler& hook, eJumpStrategy jumpStrategy = JumpPushMovRet,
    		const asmjit::X86GpReg& reg = asmjit::host::rax );
    NTSTATUS Restore( ptr_t address );

    void reset();

    NTSTATUS PrepareHook( ptr_t address, size_t maxHookSize, eJumpStrategy jumpStrategy = JumpPushMovRet,
    		const asmjit::X86GpReg& reg = asmjit::host::rax );

    NTSTATUS Detach( ptr_t address );

    size_t GetDisplacedOriginalCode( ptr_t address, uint8_t* code = nullptr );

    bool isHooked( ptr_t address ) const;

private:
    RemoteLocalHook( const RemoteLocalHook& ) = delete;
    RemoteLocalHook& operator = (const RemoteLocalHook&) = delete;

    NTSTATUS CopyOldCode( HookCtx& ctx, bool x64 );

    uint8_t GenerateJump( HookCtx& ctx, uint8_t* code, ptr_t toAddr, ptr_t fromAddr, bool x64 ) const;

private:
    class Process& _process;
    std::map<ptr_t, HookCtx> _hooks;
};

}
