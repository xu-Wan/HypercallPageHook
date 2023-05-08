#pragma once

#include <ntddk.h>
#include <intrin.h>

namespace hypercallHook {

BOOLEAN
Initialize(
);

VOID
Deinitialize(
);

using FnSwitchVirtualAddressSpace = UINT16(*)(UINT64 newCR3);

VOID
RegisterSwitchVirtualAddressSpaceHook(
	FnSwitchVirtualAddressSpace callback
);

UINT16
OriginalSwitchVirtualAddressSpace(
	UINT64 newCR3
);

}  // namespace hypercallHook
