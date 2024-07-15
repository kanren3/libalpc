#include <nt.h>
#include "runtime.h"

PVOID
NTAPI
RtAllocateZeroHeap (
    IN SIZE_T Size
)
{
    return RtlAllocateHeap(RtlGetCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Size);
}

VOID
NTAPI
RtFreeHeap (
    IN PVOID BaseAddress
)
{
    RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, BaseAddress);
}

NTSTATUS
NTAPI
RtCreateThread (
    OUT PHANDLE ThreadHandle,
    IN PUSER_THREAD_START_ROUTINE StartRoutine,
    IN PVOID Argument OPTIONAL
)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(&ObjectAttributes,
                               NULL,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    Status = NtCreateThreadEx(ThreadHandle,
                              THREAD_ALL_ACCESS,
                              &ObjectAttributes,
                              NtCurrentProcess(),
                              StartRoutine,
                              Argument,
                              0,
                              0,
                              0,
                              0,
                              NULL);

    return Status;
}
