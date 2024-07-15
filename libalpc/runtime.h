#ifndef _RUNTIME_H_
#define _RUNTIME_H_

EXTERN_C_START

PVOID
NTAPI
RtAllocateZeroHeap (
    IN SIZE_T Size
);

VOID
NTAPI
RtFreeHeap (
    IN PVOID BaseAddress
);

NTSTATUS
NTAPI
RtCreateThread (
    OUT PHANDLE ThreadHandle,
    IN PUSER_THREAD_START_ROUTINE StartRoutine,
    IN PVOID Argument OPTIONAL
);

EXTERN_C_END

#endif
