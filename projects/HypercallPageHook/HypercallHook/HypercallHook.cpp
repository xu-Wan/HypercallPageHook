#include "HypercallHook.hpp"
// https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercall-interface

extern "C" {
// nt!HvlInvokeHypercall
// Contains a reference to nt!HvcallCodeVa
_declspec(dllimport) UINT16 HvlInvokeHypercall(UINT64 HypercallInput, UINT64 Input, UINT64 Output);

// nt!HvlQueryConnection
// Test if Hyper-V is enabled
_declspec(dllimport) NTSTATUS HvlQueryConnection(PVOID *HypercallCodeVa);
}

namespace hypercallHook {
using FnInvokeHypercall = decltype(&HvlInvokeHypercall);

FnInvokeHypercall *HvcallCodeVa {};      // Address of nt!HvcallCodeVa
UINT32            *HvlEnlightenments {}, // Address of nt!HvlEnlightenments
                   originalHvlEnlightenments {};

FnSwitchVirtualAddressSpace callbackToSwitchVirtualAddressSpace {};
}  // namespace hypercallHook
using namespace hypercallHook;

extern "C" {
FnInvokeHypercall Hypercall_HypercallPage {}; // Original value of HvcallCodeVa, essentially points to
                                              // vmcall
                                              // ret
UINT16 Hypercall_HypercallPageHook(UINT64 HypercallInput, UINT64 Input, UINT64 Output);

// Hook handler for all calls to HvlSwitchVirtualAddressSpace
UINT16 Hypercall_Handle_SwitchVirtualAddressSpace(
    UINT64, UINT64 newCR3, UINT64 // 0x10001, newCR3, NULL
)
{
    if (callbackToSwitchVirtualAddressSpace)
    {
        // Delegate responsibility to switch VA space to the callback function
        return callbackToSwitchVirtualAddressSpace(newCR3);
    }
    else
    {
        return OriginalSwitchVirtualAddressSpace(newCR3);
    }
}
// Add more here...
}

BOOLEAN
hypercallHook::Initialize(
)
{
    if (!NT_SUCCESS(HvlQueryConnection(nullptr)))
        return false;

    //
    // Find the address of nt!HvcallCodeVa
    //
    for (UINT8 *it = reinterpret_cast<UINT8*>(&HvlInvokeHypercall);
                it < (reinterpret_cast<UINT8*>(&HvlInvokeHypercall) + 0x1000); ++it)
    {
        if (memcmp(it, "\x40\x32\xFF\x48\x8B\05", 6) == 0)
        {
            HvcallCodeVa = reinterpret_cast<decltype(HvcallCodeVa)>(it + 10 + *reinterpret_cast<int*>(it + 6));
            break;
        }
    }

    if (!HvcallCodeVa)
        return false;

    //
    // Find the address of HvlEnlightenments
    //
    HvlEnlightenments = reinterpret_cast<UINT32*>(&PsInitialSystemProcess) - 1;

    //
    // Overwrite the hypercall page (VA) pointer
    //
    Hypercall_HypercallPage = reinterpret_cast<decltype(Hypercall_HypercallPage)>(
        _InterlockedExchange64(reinterpret_cast<LONG64*>(HvcallCodeVa), reinterpret_cast<LONG64>(&Hypercall_HypercallPageHook)));

    //
    // Cause the kernel to transfer execution to hypervisor for context switches
    //
    originalHvlEnlightenments = _InterlockedOr(reinterpret_cast<LONG*>(HvlEnlightenments), 1); // HvSwitchVirtualAddressSpace

    return true;
}

VOID
hypercallHook::Deinitialize(
)
{
    _InterlockedExchange(reinterpret_cast<LONG*>(HvlEnlightenments), originalHvlEnlightenments);
    _InterlockedExchange64(reinterpret_cast<LONG64*>(HvcallCodeVa), reinterpret_cast<LONG64>(Hypercall_HypercallPage));
}

VOID
hypercallHook::RegisterSwitchVirtualAddressSpaceHook(
    FnSwitchVirtualAddressSpace callback
)
{
    callbackToSwitchVirtualAddressSpace = callback;
}

UINT16
hypercallHook::OriginalSwitchVirtualAddressSpace(
    UINT64 newCR3
)
{
    return Hypercall_HypercallPage(0x10001, newCR3, NULL);
}
