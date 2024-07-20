#include <nt.h>
#include "libalpc.h"

#ifndef _WIN64
#define ALPC_MAX_ALLOWED_TOTAL_LENGTH (0xFFEF)
#define ALPC_MAX_ALLOWED_DATA_LENGTH  (ALPC_MAX_ALLOWED_TOTAL_LENGTH - sizeof(PORT_MESSAGE))
#else
#define ALPC_MAX_ALLOWED_TOTAL_LENGTH (0xFFFF)
#define ALPC_MAX_ALLOWED_DATA_LENGTH  (ALPC_MAX_ALLOWED_TOTAL_LENGTH - sizeof(PORT_MESSAGE))
#endif

#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#define MIN(a,b) (((a) < (b)) ? (a) : (b))

PVOID
NTAPI
UaAllocateZeroHeap (
    IN SIZE_T Size
)
{
    return RtlAllocateHeap(RtlGetCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Size);
}

VOID
NTAPI
UaFreeHeap (
    IN PVOID BaseAddress
)
{
    RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, BaseAddress);
}

NTSTATUS
NTAPI
UaCreateThread (
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

VOID
NTAPI
UaInitializePortAttributes (
    OUT PALPC_PORT_ATTRIBUTES PortAttributes
)
{
    RtlZeroMemory(PortAttributes, sizeof(ALPC_PORT_ATTRIBUTES));

    PortAttributes->MaxMessageLength = ALPC_MAX_ALLOWED_TOTAL_LENGTH;
}

VOID
NTAPI
UaAlpcRequestHandler (
    IN PUA_SERVER Server
)
{
    NTSTATUS Status;
    PALPC_DATA_VIEW_ATTR DataViewAttribute;

    DataViewAttribute = AlpcGetMessageAttribute(Server->MessageAttributes, ALPC_MESSAGE_VIEW_ATTRIBUTE);
    RTL_ASSERT(NULL != DataViewAttribute);

    if (0 != (Server->MessageAttributes->ValidAttributes & ALPC_MESSAGE_VIEW_ATTRIBUTE)) {
        Status = NtAlpcDeleteSectionView(Server->ConnectionPortHandle, 0, DataViewAttribute->ViewBase);
        RTL_ASSERT(NT_SUCCESS(Status));
    }

    NtAlpcSendWaitReceivePort(Server->ConnectionPortHandle,
                              ALPC_MSGFLG_RELEASE_MESSAGE,
                              Server->PortMessage,
                              Server->MessageAttributes,
                              NULL,
                              NULL,
                              NULL,
                              NULL);
}

VOID
NTAPI
UaAlpcDatagramHandler (
    IN PUA_SERVER Server
)
{
    NTSTATUS Status;
    PALPC_DATA_VIEW_ATTR DataViewAttribute;
    PALPC_CONTEXT_ATTR ContextAttribute;

    DataViewAttribute = AlpcGetMessageAttribute(Server->MessageAttributes, ALPC_MESSAGE_VIEW_ATTRIBUTE);
    RTL_ASSERT(NULL != DataViewAttribute);

    ContextAttribute = AlpcGetMessageAttribute(Server->MessageAttributes, ALPC_MESSAGE_CONTEXT_ATTRIBUTE);
    RTL_ASSERT(NULL != ContextAttribute);

    if (0 != (Server->MessageAttributes->ValidAttributes & ALPC_MESSAGE_VIEW_ATTRIBUTE)) {
        Status = NtAlpcDeleteSectionView(Server->ConnectionPortHandle, 0, DataViewAttribute->ViewBase);
        RTL_ASSERT(NT_SUCCESS(Status));

        if (0 != (Server->PortMessage->u2.s2.Type & LPC_CONTINUATION_REQUIRED)) {
            NtAlpcSendWaitReceivePort(Server->ConnectionPortHandle,
                                      ALPC_MSGFLG_RELEASE_MESSAGE,
                                      Server->PortMessage,
                                      Server->MessageAttributes,
                                      NULL,
                                      NULL,
                                      NULL,
                                      NULL);
        }
    }
    else {
        if (0 != (Server->PortMessage->u2.s2.Type & LPC_CONTINUATION_REQUIRED)) {
            NtAlpcCancelMessage(Server->ConnectionPortHandle, 0, ContextAttribute);
        }
    }
}

VOID
NTAPI
UaAlpcDisconnectHandler (
    IN PUA_SERVER Server
)
{
    NTSTATUS Status;
    PALPC_CONTEXT_ATTR ContextAttribute;
    PPORT_CONTEXT PortContext;

    ContextAttribute = AlpcGetMessageAttribute(Server->MessageAttributes, ALPC_MESSAGE_CONTEXT_ATTRIBUTE);
    RTL_ASSERT(NULL != ContextAttribute);

    PortContext = ContextAttribute->PortContext;

    Status = NtClose(PortContext->CommunicationPortHandle);
    RTL_ASSERT(NT_SUCCESS(Status));

    UaFreeHeap(PortContext);
}

VOID
NTAPI
UaAlpcConnectHandler (
    IN PUA_SERVER Server
)
{
    NTSTATUS Status;
    PPORT_CONTEXT PortContext;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE CommunicationPortHandle;

    InitializeObjectAttributes(&ObjectAttributes,
                               NULL,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    if (FALSE != Server->OnConnect(Server->PortMessage)) {
        PortContext = UaAllocateZeroHeap(sizeof(PORT_CONTEXT));

        if (NULL != PortContext) {
            PortContext->ClientId = Server->PortMessage->ClientId;

            Status = NtAlpcAcceptConnectPort(&PortContext->CommunicationPortHandle,
                                             Server->ConnectionPortHandle,
                                             0,
                                             &ObjectAttributes,
                                             &Server->PortAttributes,
                                             PortContext,
                                             Server->PortMessage,
                                             NULL,
                                             TRUE);

            if (FALSE == NT_SUCCESS(Status)) {
                NtAlpcAcceptConnectPort(&CommunicationPortHandle,
                                        Server->ConnectionPortHandle,
                                        0,
                                        &ObjectAttributes,
                                        &Server->PortAttributes,
                                        NULL,
                                        Server->PortMessage,
                                        NULL,
                                        FALSE);

                UaFreeHeap(PortContext);
            }
        }
        else {
            NtAlpcAcceptConnectPort(&CommunicationPortHandle,
                                    Server->ConnectionPortHandle,
                                    0,
                                    &ObjectAttributes,
                                    &Server->PortAttributes,
                                    NULL,
                                    Server->PortMessage,
                                    NULL,
                                    FALSE);
        }
    }
    else {
        NtAlpcAcceptConnectPort(&CommunicationPortHandle,
                                Server->ConnectionPortHandle,
                                0,
                                &ObjectAttributes,
                                &Server->PortAttributes,
                                NULL,
                                Server->PortMessage,
                                NULL,
                                FALSE);
    }
}

VOID
NTAPI
UaProcessMessage (
    IN PUA_SERVER Server
)
{
    switch (LOBYTE(Server->PortMessage->u2.s2.Type)) {
    case LPC_REQUEST:
        UaAlpcRequestHandler(Server);
        break;
    case LPC_DATAGRAM:
        UaAlpcDatagramHandler(Server);
        break;
    case LPC_PORT_CLOSED:
        UaAlpcDisconnectHandler(Server);
        break;
    case LPC_CLIENT_DIED:
        UaAlpcDisconnectHandler(Server);
        break;
    case LPC_CONNECTION_REQUEST:
        UaAlpcConnectHandler(Server);
        break;
    }
}

NTSTATUS
WINAPI
UaServerWorker (
    IN PUA_SERVER Server
)
{
    NTSTATUS Status;
    SIZE_T BufferLength;

    while (TRUE) {
        BufferLength = ALPC_MAX_ALLOWED_TOTAL_LENGTH;

        Status = NtAlpcSendWaitReceivePort(Server->ConnectionPortHandle,
                                           0,
                                           NULL,
                                           NULL,
                                           Server->PortMessage,
                                           &BufferLength,
                                           Server->MessageAttributes,
                                           NULL);

        if (FALSE == NT_SUCCESS(Status)) {
            break;
        }

        UaProcessMessage(Server);
    }

    return STATUS_SUCCESS;
}

VOID
NTAPI
UaTerminateServer (
    IN PUA_SERVER Server
)
{
    NtClose(Server->ConnectionPortHandle);
    NtWaitForSingleObject(Server->ServerThreadHandle, FALSE, NULL);

    UaFreeHeap(Server->PortMessage);
    UaFreeHeap(Server->MessageAttributes);
    UaFreeHeap(Server);
}

PUA_SERVER
NTAPI
UaCreateServer (
    IN PUNICODE_STRING ServerPortName,
    IN REQUEST_PROCEDURE OnRequest,
    IN DATAGRAM_PROCEDURE OnDatagram,
    IN CONNECTION_PROCEDURE OnConnect
)
{
    NTSTATUS Status;
    PUA_SERVER Server;
    ULONG MessageAttributesMask;
    SIZE_T MessageAttributesSize;
    SIZE_T RequiredBufferSize;
    OBJECT_ATTRIBUTES ObjectAttributes;

    Server = UaAllocateZeroHeap(sizeof(UA_SERVER));

    if (NULL == Server) {
        goto Cleanup;
    }

    Server->OnRequest = OnRequest;
    Server->OnDatagram = OnDatagram;
    Server->OnConnect = OnConnect;

    MessageAttributesMask = ALPC_MESSAGE_VIEW_ATTRIBUTE | \
        ALPC_MESSAGE_CONTEXT_ATTRIBUTE;

    MessageAttributesSize = AlpcGetHeaderSize(MessageAttributesMask);

    Server->MessageAttributes = UaAllocateZeroHeap(MessageAttributesSize);

    if (NULL == Server->MessageAttributes) {
        goto Cleanup;
    }

    Status = AlpcInitializeMessageAttribute(MessageAttributesMask,
                                            Server->MessageAttributes,
                                            MessageAttributesSize,
                                            &RequiredBufferSize);

    if (FALSE == NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    Server->PortMessage = UaAllocateZeroHeap(ALPC_MAX_ALLOWED_TOTAL_LENGTH);

    if (NULL == Server->PortMessage) {
        goto Cleanup;
    }

    UaInitializePortAttributes(&Server->PortAttributes);

    InitializeObjectAttributes(&ObjectAttributes,
                               ServerPortName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    Status = NtAlpcCreatePort(&Server->ConnectionPortHandle,
                              &ObjectAttributes,
                              &Server->PortAttributes);

    if (FALSE == NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    Status = UaCreateThread(&Server->ServerThreadHandle,
                            UaServerWorker,
                            Server);

    if (FALSE == NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    return Server;

Cleanup:

    if (NULL != Server) {
        if (NULL != Server->ConnectionPortHandle) {
            NtClose(Server->ConnectionPortHandle);
        }

        if (NULL != Server->MessageAttributes) {
            UaFreeHeap(Server->MessageAttributes);
        }

        if (NULL != Server->PortMessage) {
            UaFreeHeap(Server->PortMessage);
        }

        UaFreeHeap(Server);
    }

    return NULL;
}

NTSTATUS
NTAPI
UaSendSectionSynchronousRequest (
    IN HANDLE CommunicationPortHandle,
    IN PVOID RequestDataBuffer,
    IN ULONG RequestDataLength,
    OUT PVOID ResponseDataBuffer,
    IN ULONG ResponseDataLength,
    OUT PULONG NumberOfBytesResponse
)
{
    NTSTATUS Status;
    SIZE_T SectionRequestMessageLength;
    PPORT_SECTION_MESSAGE SectionRequestMessage = NULL;
    PALPC_MESSAGE_ATTRIBUTES MessageAttributes = NULL;
    SIZE_T MessageAttributesSize;
    SIZE_T RequiredBufferSize;
    PALPC_DATA_VIEW_ATTR DataViewAttribute;
    ALPC_HANDLE SectionHandle = NULL;
    SIZE_T ActualSectionSize;

    SectionRequestMessageLength = sizeof(PORT_SECTION_MESSAGE);
    SectionRequestMessage = UaAllocateZeroHeap(SectionRequestMessageLength);

    if (NULL == SectionRequestMessage) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    SectionRequestMessage->MessageHeader.u1.s1.TotalLength = (USHORT)(SectionRequestMessageLength);
    SectionRequestMessage->MessageHeader.u1.s1.DataLength = (USHORT)(SectionRequestMessageLength - sizeof(PORT_MESSAGE));

    SectionRequestMessage->ValidDataLength = MAX(RequestDataLength, ResponseDataLength);

    MessageAttributesSize = AlpcGetHeaderSize(ALPC_MESSAGE_VIEW_ATTRIBUTE);
    MessageAttributes = UaAllocateZeroHeap(MessageAttributesSize);

    if (NULL == MessageAttributes) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    Status = AlpcInitializeMessageAttribute(ALPC_MESSAGE_VIEW_ATTRIBUTE,
                                            MessageAttributes,
                                            MessageAttributesSize,
                                            &RequiredBufferSize);

    if (FALSE == NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    Status = NtAlpcCreatePortSection(CommunicationPortHandle,
                                     0,
                                     NULL,
                                     MAX(RequestDataLength, ResponseDataLength),
                                     &SectionHandle,
                                     &ActualSectionSize);

    if (FALSE == NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    MessageAttributes->ValidAttributes |= ALPC_MESSAGE_VIEW_ATTRIBUTE;

    DataViewAttribute = AlpcGetMessageAttribute(MessageAttributes, ALPC_MESSAGE_VIEW_ATTRIBUTE);
    RTL_ASSERT(NULL != DataViewAttribute);

    DataViewAttribute->SectionHandle = SectionHandle;
    DataViewAttribute->ViewBase = NULL;
    DataViewAttribute->ViewSize = MAX(RequestDataLength, ResponseDataLength);
    DataViewAttribute->Flags = 0;

    Status = NtAlpcCreateSectionView(CommunicationPortHandle, 0, DataViewAttribute);

    if (FALSE == NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    if (NULL != RequestDataBuffer) {
        RtlCopyMemory(DataViewAttribute->ViewBase, RequestDataBuffer, RequestDataLength);
    }

    DataViewAttribute->Flags = ALPC_VIEWFLG_UNMAP_EXISTING;

    Status = NtAlpcSendWaitReceivePort(CommunicationPortHandle,
                                       ALPC_MSGFLG_SYNC_REQUEST,
                                       &SectionRequestMessage->MessageHeader,
                                       MessageAttributes,
                                       &SectionRequestMessage->MessageHeader,
                                       &SectionRequestMessageLength,
                                       NULL,
                                       NULL);

    if (FALSE == NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    if (FALSE != NT_SUCCESS(Status)) {
        *NumberOfBytesResponse = SectionRequestMessage->ValidDataLength;
        RtlCopyMemory(ResponseDataBuffer, DataViewAttribute->ViewBase, SectionRequestMessage->ValidDataLength);
    }

    Status = NtAlpcDeleteSectionView(CommunicationPortHandle, 0, DataViewAttribute->ViewBase);
    RTL_ASSERT(NT_SUCCESS(Status));

    Status = NtAlpcDeletePortSection(CommunicationPortHandle, 0, SectionHandle);
    RTL_ASSERT(NT_SUCCESS(Status));

    UaFreeHeap(MessageAttributes);
    UaFreeHeap(SectionRequestMessage);

    return STATUS_SUCCESS;

Cleanup:

    if (NULL != SectionHandle) {
        NtAlpcDeletePortSection(CommunicationPortHandle, 0, SectionHandle);
    }

    if (NULL != MessageAttributes) {
        UaFreeHeap(MessageAttributes);
    }

    if (NULL != SectionRequestMessage) {
        UaFreeHeap(SectionRequestMessage);
    }

    return Status;
}

NTSTATUS
NTAPI
UaSendSynchronousRequest (
    IN HANDLE CommunicationPortHandle,
    IN PVOID RequestDataBuffer,
    IN ULONG RequestDataLength,
    OUT PVOID ResponseDataBuffer,
    IN ULONG ResponseDataLength,
    OUT PULONG NumberOfBytesResponse
)
{
    NTSTATUS Status;
    SIZE_T RequestMessageLength;
    PPORT_MESSAGE RequestMessage;

    if (MAX(RequestDataLength, ResponseDataLength) > ALPC_MAX_ALLOWED_DATA_LENGTH) {
        return UaSendSectionSynchronousRequest(CommunicationPortHandle,
                                               RequestDataBuffer,
                                               RequestDataLength,
                                               ResponseDataBuffer,
                                               ResponseDataLength,
                                               NumberOfBytesResponse);
    }

    RequestMessageLength = sizeof(PORT_MESSAGE) + MAX(RequestDataLength, ResponseDataLength);
    RequestMessage = UaAllocateZeroHeap(RequestMessageLength);

    if (NULL == RequestMessage) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RequestMessage->u1.s1.TotalLength = (USHORT)(RequestMessageLength);
    RequestMessage->u1.s1.DataLength = (USHORT)(RequestDataLength);

    if (NULL != RequestMessage) {
        RtlCopyMemory(RequestMessage + 1, RequestDataBuffer, RequestDataLength);
    }

    Status = NtAlpcSendWaitReceivePort(CommunicationPortHandle,
                                       ALPC_MSGFLG_SYNC_REQUEST,
                                       RequestMessage,
                                       NULL,
                                       RequestMessage,
                                       &RequestMessageLength,
                                       NULL,
                                       NULL);

    if (FALSE != NT_SUCCESS(Status)) {
        *NumberOfBytesResponse = RequestMessage->u1.s1.DataLength;
        RtlCopyMemory(ResponseDataBuffer, RequestMessage + 1, RequestMessage->u1.s1.DataLength);
    }

    UaFreeHeap(RequestMessage);

    return Status;
}

NTSTATUS
NTAPI
UaSendSectionDatagram (
    IN HANDLE CommunicationPortHandle,
    IN PVOID DatagramDataBuffer OPTIONAL,
    IN ULONG DatagramDataLength
)
{
    NTSTATUS Status;
    SIZE_T SectionDatagramMessageLength;
    PPORT_SECTION_MESSAGE SectionDatagramMessage = NULL;
    PALPC_MESSAGE_ATTRIBUTES MessageAttributes = NULL;
    SIZE_T MessageAttributesSize;
    SIZE_T RequiredBufferSize;
    PALPC_DATA_VIEW_ATTR DataViewAttribute;
    ALPC_HANDLE SectionHandle = NULL;
    SIZE_T ActualSectionSize;

    SectionDatagramMessageLength = sizeof(PORT_SECTION_MESSAGE);
    SectionDatagramMessage = UaAllocateZeroHeap(SectionDatagramMessageLength);

    if (NULL == SectionDatagramMessage) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    SectionDatagramMessage->MessageHeader.u1.s1.TotalLength = (USHORT)(SectionDatagramMessageLength);
    SectionDatagramMessage->MessageHeader.u1.s1.DataLength = (USHORT)(SectionDatagramMessageLength - sizeof(PORT_MESSAGE));

    SectionDatagramMessage->ValidDataLength = DatagramDataLength;

    MessageAttributesSize = AlpcGetHeaderSize(ALPC_MESSAGE_VIEW_ATTRIBUTE);
    MessageAttributes = UaAllocateZeroHeap(MessageAttributesSize);

    if (NULL == MessageAttributes) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    Status = AlpcInitializeMessageAttribute(ALPC_MESSAGE_VIEW_ATTRIBUTE,
                                            MessageAttributes,
                                            MessageAttributesSize,
                                            &RequiredBufferSize);

    if (FALSE == NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    Status = NtAlpcCreatePortSection(CommunicationPortHandle,
                                     0,
                                     NULL,
                                     DatagramDataLength,
                                     &SectionHandle,
                                     &ActualSectionSize);

    if (FALSE == NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    MessageAttributes->ValidAttributes |= ALPC_MESSAGE_VIEW_ATTRIBUTE;

    DataViewAttribute = AlpcGetMessageAttribute(MessageAttributes, ALPC_MESSAGE_VIEW_ATTRIBUTE);
    RTL_ASSERT(NULL != DataViewAttribute);

    DataViewAttribute->SectionHandle = SectionHandle;
    DataViewAttribute->ViewBase = NULL;
    DataViewAttribute->ViewSize = DatagramDataLength;
    DataViewAttribute->Flags = 0;

    Status = NtAlpcCreateSectionView(CommunicationPortHandle, 0, DataViewAttribute);

    if (FALSE == NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    if (NULL != DatagramDataBuffer) {
        RtlCopyMemory(DataViewAttribute->ViewBase, DatagramDataBuffer, DatagramDataLength);
    }

    DataViewAttribute->Flags = ALPC_VIEWFLG_UNMAP_EXISTING;

    Status = NtAlpcSendWaitReceivePort(CommunicationPortHandle,
                                       ALPC_MSGFLG_RELEASE_MESSAGE,
                                       &SectionDatagramMessage->MessageHeader,
                                       MessageAttributes,
                                       NULL,
                                       &SectionDatagramMessageLength,
                                       NULL,
                                       NULL);

    if (FALSE == NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    Status = NtAlpcDeleteSectionView(CommunicationPortHandle, 0, DataViewAttribute->ViewBase);
    RTL_ASSERT(NT_SUCCESS(Status));

    Status = NtAlpcDeletePortSection(CommunicationPortHandle, 0, SectionHandle);
    RTL_ASSERT(NT_SUCCESS(Status));

    UaFreeHeap(MessageAttributes);
    UaFreeHeap(SectionDatagramMessage);

    return STATUS_SUCCESS;

Cleanup:

    if (NULL != SectionHandle) {
        NtAlpcDeletePortSection(CommunicationPortHandle, 0, SectionHandle);
    }

    if (NULL != MessageAttributes) {
        UaFreeHeap(MessageAttributes);
    }

    if (NULL != SectionDatagramMessage) {
        UaFreeHeap(SectionDatagramMessage);
    }

    return Status;
}

NTSTATUS
NTAPI
UaSendDatagram (
    IN HANDLE CommunicationPortHandle,
    IN PVOID DatagramDataBuffer OPTIONAL,
    IN ULONG DatagramDataLength
)
{
    NTSTATUS Status;
    SIZE_T DatagramMessageLength;
    PPORT_MESSAGE DatagramMessage;

    if (DatagramDataLength > ALPC_MAX_ALLOWED_DATA_LENGTH) {
        return UaSendSectionDatagram(CommunicationPortHandle,
                                     DatagramDataBuffer,
                                     DatagramDataLength);
    }

    DatagramMessageLength = sizeof(PORT_MESSAGE) + DatagramDataLength;
    DatagramMessage = UaAllocateZeroHeap(DatagramMessageLength);

    if (NULL == DatagramMessage) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DatagramMessage->u1.s1.TotalLength = (USHORT)(DatagramMessageLength);
    DatagramMessage->u1.s1.DataLength = (USHORT)(DatagramDataLength);

    if (NULL != DatagramDataBuffer) {
        RtlCopyMemory(DatagramMessage + 1, DatagramDataBuffer, DatagramDataLength);
    }

    Status = NtAlpcSendWaitReceivePort(CommunicationPortHandle,
                                       ALPC_MSGFLG_RELEASE_MESSAGE,
                                       DatagramMessage,
                                       NULL,
                                       NULL,
                                       &DatagramMessageLength,
                                       NULL,
                                       NULL);

    UaFreeHeap(DatagramMessage);

    return STATUS_SUCCESS;
}

VOID
NTAPI
UaDisconnectServer (
    IN HANDLE CommunicationPortHandle
)
{
    NtClose(CommunicationPortHandle);
}

NTSTATUS
NTAPI
UaConnectServer (
    OUT PHANDLE CommunicationPortHandle,
    IN PUNICODE_STRING ServerPortName,
    IN PVOID ConnectionDataBuffer OPTIONAL,
    IN USHORT ConnectionDataLength
)
{
    NTSTATUS Status;
    SIZE_T ConnectionMessageLength;
    PPORT_MESSAGE ConnectionMessage;
    OBJECT_ATTRIBUTES ObjectAttributes;
    ALPC_PORT_ATTRIBUTES PortAttributes;

    if (ConnectionDataLength > ALPC_MAX_ALLOWED_DATA_LENGTH) {
        return STATUS_BUFFER_OVERFLOW;
    }

    ConnectionMessageLength = sizeof(PORT_MESSAGE) + ConnectionDataLength;
    ConnectionMessage = UaAllocateZeroHeap(ConnectionMessageLength);

    if (NULL == ConnectionMessage) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ConnectionMessage->u1.s1.TotalLength = (USHORT)(ConnectionMessageLength);
    ConnectionMessage->u1.s1.DataLength = ConnectionDataLength;

    if (NULL != ConnectionDataBuffer) {
        RtlCopyMemory(ConnectionMessage + 1, ConnectionDataBuffer, ConnectionDataLength);
    }

    InitializeObjectAttributes(&ObjectAttributes,
                               NULL,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    UaInitializePortAttributes(&PortAttributes);

    Status = NtAlpcConnectPort(CommunicationPortHandle,
                               ServerPortName,
                               &ObjectAttributes,
                               &PortAttributes,
                               ALPC_MSGFLG_SYNC_REQUEST,
                               NULL,
                               ConnectionMessage,
                               &ConnectionMessageLength,
                               NULL,
                               NULL,
                               NULL);

    UaFreeHeap(ConnectionMessage);

    return Status;
}
