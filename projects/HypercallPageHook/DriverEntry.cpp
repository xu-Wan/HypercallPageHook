#include "HypercallHook/HypercallHook.hpp"

#define DEBUG_PRINT(Format, ...) DbgPrint("[HypercallHook]" Format, __VA_ARGS__)

UINT16
HookedSwitchVirtualAddressSpace(
    UINT64 newCR3
)
{
    DEBUG_PRINT("SwitchVirtualAddressSpace | NewCR3 = 0x%llX, Processor = 0x%X\n", newCR3, KeGetCurrentProcessorIndex());
    return hypercallHook::OriginalSwitchVirtualAddressSpace(newCR3);
}

[[maybe_unused]] VOID
DriverUnload(
)
{
    hypercallHook::Deinitialize();
}

NTSTATUS
DriverEntry(
)
{
    if (!hypercallHook::Initialize())
    {
        DEBUG_PRINT("Initialize failed. Maybe Hyper-V isn't enabled?");
        return STATUS_UNSUCCESSFUL;
    }

    hypercallHook::RegisterSwitchVirtualAddressSpaceHook(&HookedSwitchVirtualAddressSpace);
    DEBUG_PRINT("Hook registered");

    return STATUS_SUCCESS;
}
