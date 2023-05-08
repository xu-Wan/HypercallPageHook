EXTERN Hypercall_HypercallPage : QWORD
EXTERN Hypercall_Handle_SwitchVirtualAddressSpace : PROC

.CODE

Hypercall_HypercallPageHook PROC

	; Example of hooking HvlSwitchVirtualAddressSpace
	cmp rcx, 10001h
	je Hypercall_Handle_SwitchVirtualAddressSpace

	; Add more here...

	jmp Hypercall_HypercallPage
Hypercall_HypercallPageHook ENDP

END