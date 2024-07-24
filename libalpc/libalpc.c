#include <nt.h>
#include "libalpc.h"

#ifndef _WIN64
#define ALPC_MAX_ALLOWED_TOTAL_LENGTH (0xFFEF)
#else
#define ALPC_MAX_ALLOWED_TOTAL_LENGTH (0xFFFF)
#endif

#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#define MIN(a,b) (((a) < (b)) ? (a) : (b))

typedef struct _PORT_CONTEXT {
    CLIENT_ID ClientId;
    HANDLE CommunicationPortHandle;
} PORT_CONTEXT, *PPORT_CONTEXT;

typedef struct _REQUEST_PORT_MESSAGE {
    PORT_MESSAGE Header;
    ULONG RequestBufferLength;
    ULONG ResponseBufferLength;
    ULONG NumberOfResponse;
    NTSTATUS ResponseStatus;
} REQUEST_PORT_MESSAGE, *PREQUEST_PORT_MESSAGE;

typedef struct _DATAGRAM_PORT_MESSAGE {
    PORT_MESSAGE Header;
    ULONG DatagramBufferLength;
} DATAGRAM_PORT_MESSAGE, *PDATAGRAM_PORT_MESSAGE;

typedef struct _CONNECTION_PORT_MESSAGE {
    PORT_MESSAGE Header;
    USHORT ConnectionBufferLength;
} CONNECTION_PORT_MESSAGE, *PCONNECTION_PORT_MESSAGE;

typedef struct _UA_SERVER {
    REQUEST_PROCEDURE OnRequest;
    DATAGRAM_PROCEDURE OnDatagram;
    CONNECTION_PROCEDURE OnConnect;
    PPORT_MESSAGE PortMessage;
    ALPC_PORT_ATTRIBUTES PortAttributes;
    PALPC_MESSAGE_ATTRIBUTES MessageAttributes;
    HANDLE ConnectionPortHandle;
    HANDLE ServerThreadHandle;
} UA_SERVER, *PUA_SERVER;

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
    PREQUEST_PORT_MESSAGE RequestMessage;
    ULONG MaxBufferLength;
    ULONG TotalLength;
    PVOID ShareBuffer;

    DataViewAttribute = AlpcGetMessageAttribute(Server->MessageAttributes, ALPC_MESSAGE_VIEW_ATTRIBUTE);
    RTL_ASSERT(NULL != DataViewAttribute);

    RequestMessage = CONTAINING_RECORD(Server->PortMessage, REQUEST_PORT_MESSAGE, Header);

    MaxBufferLength = MAX(RequestMessage->RequestBufferLength, RequestMessage->ResponseBufferLength);

    if (0 != (Server->MessageAttributes->ValidAttributes & ALPC_MESSAGE_VIEW_ATTRIBUTE)) {
        if (MaxBufferLength <= DataViewAttribute->ViewSize) {
            ShareBuffer = DataViewAttribute->ViewBase;

            Status = Server->OnRequest(&RequestMessage->Header.ClientId,
                                       ShareBuffer,
                                       RequestMessage->RequestBufferLength,
                                       RequestMessage->ResponseBufferLength,
                                       &RequestMessage->NumberOfResponse);

            RequestMessage->ResponseStatus = Status;
        }


        Status = NtAlpcDeleteSectionView(Server->ConnectionPortHandle, 0, DataViewAttribute->ViewBase);
        RTL_ASSERT(NT_SUCCESS(Status));
    }
    else {
        TotalLength = (USHORT)(RequestMessage->Header.u1.s1.TotalLength);

        if (MaxBufferLength + sizeof(REQUEST_PORT_MESSAGE) == TotalLength) {
            ShareBuffer = RequestMessage + 1;

            Status = Server->OnRequest(&RequestMessage->Header.ClientId,
                                       ShareBuffer,
                                       RequestMessage->RequestBufferLength,
                                       RequestMessage->ResponseBufferLength,
                                       &RequestMessage->NumberOfResponse);

            RequestMessage->ResponseStatus = Status;
        }
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
    PDATAGRAM_PORT_MESSAGE DatagramMessage;
    PVOID DatagramBuffer;
    ULONG TotalLength;

    DataViewAttribute = AlpcGetMessageAttribute(Server->MessageAttributes, ALPC_MESSAGE_VIEW_ATTRIBUTE);
    RTL_ASSERT(NULL != DataViewAttribute);

    ContextAttribute = AlpcGetMessageAttribute(Server->MessageAttributes, ALPC_MESSAGE_CONTEXT_ATTRIBUTE);
    RTL_ASSERT(NULL != ContextAttribute);

    DatagramMessage = CONTAINING_RECORD(Server->PortMessage, DATAGRAM_PORT_MESSAGE, Header);

    if (0 != (Server->MessageAttributes->ValidAttributes & ALPC_MESSAGE_VIEW_ATTRIBUTE)) {
        if (DatagramMessage->DatagramBufferLength <= DataViewAttribute->ViewSize) {
            DatagramBuffer = DataViewAttribute->ViewBase;

            Server->OnDatagram(&DatagramMessage->Header.ClientId,
                               DatagramBuffer,
                               DatagramMessage->DatagramBufferLength);
        }

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
        TotalLength = (USHORT)(DatagramMessage->Header.u1.s1.TotalLength);

        if (DatagramMessage->DatagramBufferLength + sizeof(DATAGRAM_PORT_MESSAGE) == TotalLength) {
            DatagramBuffer = DatagramMessage + 1;

            Server->OnDatagram(&DatagramMessage->Header.ClientId,
                               DatagramBuffer,
                               DatagramMessage->DatagramBufferLength);
        }

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
    PCONNECTION_PORT_MESSAGE ConnectionMessage;
    ULONG TotalLength;
    BOOLEAN AcceptConnect;
    PPORT_CONTEXT PortContext;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE CommunicationPortHandle;

    InitializeObjectAttributes(&ObjectAttributes,
                               NULL,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    ConnectionMessage = CONTAINING_RECORD(Server->PortMessage, CONNECTION_PORT_MESSAGE, Header);

    TotalLength = (USHORT)(ConnectionMessage->Header.u1.s1.TotalLength);

    if (ConnectionMessage->ConnectionBufferLength + sizeof(CONNECTION_PORT_MESSAGE) != TotalLength) {
        AcceptConnect = FALSE;
    }
    else {
        AcceptConnect = Server->OnConnect(&ConnectionMessage->Header.ClientId,
                                          ConnectionMessage + 1,
                                          ConnectionMessage->ConnectionBufferLength);
    }

    if (FALSE != AcceptConnect) {
        PortContext = UaAllocateZeroHeap(sizeof(PORT_CONTEXT));

        if (NULL != PortContext) {
            PortContext->ClientId = ConnectionMessage->Header.ClientId;

            Status = NtAlpcAcceptConnectPort(&PortContext->CommunicationPortHandle,
                                             Server->ConnectionPortHandle,
                                             0,
                                             &ObjectAttributes,
                                             &Server->PortAttributes,
                                             PortContext,
                                             &ConnectionMessage->Header,
                                             NULL,
                                             TRUE);

            if (FALSE == NT_SUCCESS(Status)) {
                NtAlpcAcceptConnectPort(&CommunicationPortHandle,
                                        Server->ConnectionPortHandle,
                                        0,
                                        &ObjectAttributes,
                                        &Server->PortAttributes,
                                        NULL,
                                        &ConnectionMessage->Header,
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
                                    &ConnectionMessage->Header,
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
                                &ConnectionMessage->Header,
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
    IN PVOID RequestBuffer,
    IN ULONG RequestBufferLength,
    OUT PVOID ResponseBuffer,
    IN ULONG ResponseBufferLength,
    OUT PULONG NumberOfResponse OPTIONAL,
    OUT PNTSTATUS ResponseStatus OPTIONAL
)
{
    NTSTATUS Status;
    SIZE_T RequestMessageLength;
    PREQUEST_PORT_MESSAGE RequestMessage = NULL;
    PALPC_MESSAGE_ATTRIBUTES MessageAttributes = NULL;
    SIZE_T MessageAttributesSize;
    SIZE_T RequiredBufferSize;
    PALPC_DATA_VIEW_ATTR DataViewAttribute;
    ALPC_HANDLE SectionHandle = NULL;
    SIZE_T ActualSectionSize;

    RequestMessageLength = sizeof(REQUEST_PORT_MESSAGE);
    RequestMessage = UaAllocateZeroHeap(RequestMessageLength);

    if (NULL == RequestMessage) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RequestMessage->Header.u1.s1.TotalLength = (USHORT)(RequestMessageLength);
    RequestMessage->Header.u1.s1.DataLength = (USHORT)(RequestMessageLength - sizeof(PORT_MESSAGE));

    RequestMessage->RequestBufferLength = RequestBufferLength;
    RequestMessage->ResponseBufferLength = ResponseBufferLength;

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
                                     MAX(RequestBufferLength, ResponseBufferLength),
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
    DataViewAttribute->ViewSize = MAX(RequestBufferLength, ResponseBufferLength);
    DataViewAttribute->Flags = 0;

    Status = NtAlpcCreateSectionView(CommunicationPortHandle, 0, DataViewAttribute);

    if (FALSE == NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    if (NULL != RequestBuffer) {
        RtlCopyMemory(DataViewAttribute->ViewBase, RequestBuffer, RequestBufferLength);
    }

    DataViewAttribute->Flags = ALPC_VIEWFLG_UNMAP_EXISTING;

    Status = NtAlpcSendWaitReceivePort(CommunicationPortHandle,
                                       ALPC_MSGFLG_SYNC_REQUEST,
                                       &RequestMessage->Header,
                                       MessageAttributes,
                                       &RequestMessage->Header,
                                       &RequestMessageLength,
                                       NULL,
                                       NULL);

    if (FALSE == NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    if (FALSE != NT_SUCCESS(Status)) {
        if (NULL != NumberOfResponse) {
            *NumberOfResponse = RequestMessage->NumberOfResponse;
        }

        if (NULL != ResponseStatus) {
            *ResponseStatus = RequestMessage->ResponseStatus;
        }

        if (NULL != ResponseBuffer) {
            RtlCopyMemory(ResponseBuffer, RequestMessage + 1, RequestMessage->NumberOfResponse);
        }
    }

    Status = NtAlpcDeleteSectionView(CommunicationPortHandle, 0, DataViewAttribute->ViewBase);
    RTL_ASSERT(NT_SUCCESS(Status));

    Status = NtAlpcDeletePortSection(CommunicationPortHandle, 0, SectionHandle);
    RTL_ASSERT(NT_SUCCESS(Status));

    UaFreeHeap(MessageAttributes);
    UaFreeHeap(RequestMessage);

    return STATUS_SUCCESS;

Cleanup:

    if (NULL != SectionHandle) {
        NtAlpcDeletePortSection(CommunicationPortHandle, 0, SectionHandle);
    }

    if (NULL != MessageAttributes) {
        UaFreeHeap(MessageAttributes);
    }

    if (NULL != RequestMessage) {
        UaFreeHeap(RequestMessage);
    }

    return Status;
}

NTSTATUS
NTAPI
UaSendSynchronousRequest (
    IN HANDLE CommunicationPortHandle,
    IN PVOID RequestBuffer,
    IN ULONG RequestBufferLength,
    OUT PVOID ResponseBuffer,
    IN ULONG ResponseBufferLength,
    OUT PULONG NumberOfResponse OPTIONAL,
    OUT PNTSTATUS ResponseStatus OPTIONAL
)
{
    NTSTATUS Status;
    USHORT MaxAllowedDataLength;
    SIZE_T RequestMessageLength;
    PREQUEST_PORT_MESSAGE RequestMessage;

    MaxAllowedDataLength = ALPC_MAX_ALLOWED_TOTAL_LENGTH - sizeof(REQUEST_PORT_MESSAGE);

    if (MAX(RequestBufferLength, ResponseBufferLength) > MaxAllowedDataLength) {
        return UaSendSectionSynchronousRequest(CommunicationPortHandle,
                                               RequestBuffer,
                                               RequestBufferLength,
                                               ResponseBuffer,
                                               ResponseBufferLength,
                                               NumberOfResponse,
                                               ResponseStatus);
    }

    RequestMessageLength = sizeof(REQUEST_PORT_MESSAGE) + MAX(RequestBufferLength, ResponseBufferLength);
    RequestMessage = UaAllocateZeroHeap(RequestMessageLength);

    if (NULL == RequestMessage) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RequestMessage->Header.u1.s1.TotalLength = (USHORT)(RequestMessageLength);
    RequestMessage->Header.u1.s1.DataLength = (USHORT)(RequestMessageLength - sizeof(PORT_MESSAGE));

    RequestMessage->RequestBufferLength = RequestBufferLength;
    RequestMessage->ResponseBufferLength = ResponseBufferLength;

    if (NULL != RequestMessage) {
        RtlCopyMemory(RequestMessage + 1, RequestBuffer, RequestBufferLength);
    }

    Status = NtAlpcSendWaitReceivePort(CommunicationPortHandle,
                                       ALPC_MSGFLG_SYNC_REQUEST,
                                       &RequestMessage->Header,
                                       NULL,
                                       &RequestMessage->Header,
                                       &RequestMessageLength,
                                       NULL,
                                       NULL);

    if (FALSE != NT_SUCCESS(Status)) {
        if (NULL != NumberOfResponse) {
            *NumberOfResponse = RequestMessage->NumberOfResponse;
        }

        if (NULL != ResponseStatus) {
            *ResponseStatus = RequestMessage->ResponseStatus;
        }

        if (NULL != ResponseBuffer) {
            RtlCopyMemory(ResponseBuffer, RequestMessage + 1, RequestMessage->NumberOfResponse);
        }
    }

    UaFreeHeap(RequestMessage);

    return Status;
}

NTSTATUS
NTAPI
UaSendSectionDatagram (
    IN HANDLE CommunicationPortHandle,
    IN PVOID DatagramBuffer OPTIONAL,
    IN ULONG DatagramBufferLength
)
{
    NTSTATUS Status;
    SIZE_T DatagramMessageLength;
    PDATAGRAM_PORT_MESSAGE DatagramMessage = NULL;
    PALPC_MESSAGE_ATTRIBUTES MessageAttributes = NULL;
    SIZE_T MessageAttributesSize;
    SIZE_T RequiredBufferSize;
    PALPC_DATA_VIEW_ATTR DataViewAttribute;
    ALPC_HANDLE SectionHandle = NULL;
    SIZE_T ActualSectionSize;

    DatagramMessageLength = sizeof(DATAGRAM_PORT_MESSAGE);
    DatagramMessage = UaAllocateZeroHeap(DatagramMessageLength);

    if (NULL == DatagramMessage) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    DatagramMessage->Header.u1.s1.TotalLength = (USHORT)(DatagramMessageLength);
    DatagramMessage->Header.u1.s1.DataLength = (USHORT)(DatagramMessageLength - sizeof(PORT_MESSAGE));

    DatagramMessage->DatagramBufferLength = DatagramBufferLength;

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
                                     DatagramBufferLength,
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
    DataViewAttribute->ViewSize = DatagramBufferLength;
    DataViewAttribute->Flags = 0;

    Status = NtAlpcCreateSectionView(CommunicationPortHandle, 0, DataViewAttribute);

    if (FALSE == NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    if (NULL != DatagramBuffer) {
        RtlCopyMemory(DataViewAttribute->ViewBase, DatagramBuffer, DatagramBufferLength);
    }

    DataViewAttribute->Flags = ALPC_VIEWFLG_UNMAP_EXISTING;

    Status = NtAlpcSendWaitReceivePort(CommunicationPortHandle,
                                       ALPC_MSGFLG_RELEASE_MESSAGE,
                                       &DatagramMessage->Header,
                                       MessageAttributes,
                                       NULL,
                                       &DatagramMessageLength,
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
    UaFreeHeap(DatagramMessage);

    return STATUS_SUCCESS;

Cleanup:

    if (NULL != SectionHandle) {
        NtAlpcDeletePortSection(CommunicationPortHandle, 0, SectionHandle);
    }

    if (NULL != MessageAttributes) {
        UaFreeHeap(MessageAttributes);
    }

    if (NULL != DatagramMessage) {
        UaFreeHeap(DatagramMessage);
    }

    return Status;
}

NTSTATUS
NTAPI
UaSendDatagram (
    IN HANDLE CommunicationPortHandle,
    IN PVOID DatagramBuffer OPTIONAL,
    IN ULONG DatagramBufferLength
)
{
    NTSTATUS Status;
    USHORT MaxAllowedDataLength;
    SIZE_T DatagramMessageLength;
    PDATAGRAM_PORT_MESSAGE DatagramMessage;

    MaxAllowedDataLength = ALPC_MAX_ALLOWED_TOTAL_LENGTH - sizeof(DATAGRAM_PORT_MESSAGE);

    if (DatagramBufferLength > MaxAllowedDataLength) {
        return UaSendSectionDatagram(CommunicationPortHandle,
                                     DatagramBuffer,
                                     DatagramBufferLength);
    }

    DatagramMessageLength = sizeof(DATAGRAM_PORT_MESSAGE) + DatagramBufferLength;
    DatagramMessage = UaAllocateZeroHeap(DatagramMessageLength);

    if (NULL == DatagramMessage) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DatagramMessage->Header.u1.s1.TotalLength = (USHORT)(DatagramMessageLength);
    DatagramMessage->Header.u1.s1.DataLength = (USHORT)(DatagramMessageLength - sizeof(PORT_MESSAGE));

    DatagramMessage->DatagramBufferLength = DatagramBufferLength;

    if (NULL != DatagramBuffer) {
        RtlCopyMemory(DatagramMessage + 1, DatagramBuffer, DatagramBufferLength);
    }

    Status = NtAlpcSendWaitReceivePort(CommunicationPortHandle,
                                       ALPC_MSGFLG_RELEASE_MESSAGE,
                                       &DatagramMessage->Header,
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
    IN PVOID ConnectionBuffer OPTIONAL,
    IN USHORT ConnectionBufferLength
)
{
    NTSTATUS Status;
    USHORT MaxAllowedDataLength;
    SIZE_T ConnectionMessageLength;
    PCONNECTION_PORT_MESSAGE ConnectionMessage;
    OBJECT_ATTRIBUTES ObjectAttributes;
    ALPC_PORT_ATTRIBUTES PortAttributes;

    MaxAllowedDataLength = ALPC_MAX_ALLOWED_TOTAL_LENGTH - sizeof(CONNECTION_PORT_MESSAGE);

    if (ConnectionBufferLength > MaxAllowedDataLength) {
        return STATUS_BUFFER_OVERFLOW;
    }

    ConnectionMessageLength = sizeof(CONNECTION_PORT_MESSAGE) + ConnectionBufferLength;
    ConnectionMessage = UaAllocateZeroHeap(ConnectionMessageLength);

    if (NULL == ConnectionMessage) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ConnectionMessage->Header.u1.s1.TotalLength = (USHORT)(ConnectionMessageLength);
    ConnectionMessage->Header.u1.s1.DataLength = (USHORT)(ConnectionMessageLength - sizeof(PORT_MESSAGE));

    ConnectionMessage->ConnectionBufferLength = ConnectionBufferLength;

    if (NULL != ConnectionBuffer) {
        RtlCopyMemory(ConnectionMessage + 1, ConnectionBuffer, ConnectionBufferLength);
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
                               &ConnectionMessage->Header,
                               &ConnectionMessageLength,
                               NULL,
                               NULL,
                               NULL);

    UaFreeHeap(ConnectionMessage);

    return Status;
}
