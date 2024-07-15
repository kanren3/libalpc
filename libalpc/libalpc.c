#include <nt.h>
#include "runtime.h"
#include "libalpc.h"

#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#define MIN(a,b) (((a) < (b)) ? (a) : (b))

PVOID
NTAPI
UaAllocateZeroHeap (
    IN SIZE_T Size
)
{
    PVOID BaseAddress;

    BaseAddress = RtAllocateZeroHeap(Size);

    return BaseAddress;
}

VOID
NTAPI
UaFreeHeap (
    IN PVOID BaseAddress
)
{
    RtFreeHeap(BaseAddress);
}

VOID
NTAPI
UaInitializePortAttributes (
    OUT PALPC_PORT_ATTRIBUTES PortAttributes
)
{
    RtlZeroMemory(PortAttributes, sizeof(ALPC_PORT_ATTRIBUTES));

    PortAttributes->MaxMessageLength = ALPC_MAX_ALLOWED_MESSAGE_LENGTH;
}

NTSTATUS
NTAPI
UaAlpcRequest (
    IN PUA_SERVER Server
)
{
    Server->OnRequest(Server->PortMessage);

    NtAlpcSendWaitReceivePort(Server->ConnectionPortHandle,
                              ALPC_MSGFLG_RELEASE_MESSAGE,
                              Server->PortMessage,
                              NULL,
                              NULL,
                              NULL,
                              NULL,
                              NULL);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
UaAlpcDatagram (
    IN PUA_SERVER Server
)
{
    PALPC_CONTEXT_ATTR ContextAttribute;

    ContextAttribute = AlpcGetMessageAttribute(Server->MessageAttributes,
                                               ALPC_MESSAGE_CONTEXT_ATTRIBUTE);

    if (NULL == ContextAttribute) {
        return STATUS_UNSUCCESSFUL;
    }

    Server->OnDatagram(Server->PortMessage);

    if (0 != (Server->PortMessage->u2.s2.Type & LPC_CONTINUATION_REQUIRED)) {
        NtAlpcCancelMessage(Server->ConnectionPortHandle, 0, ContextAttribute);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
UaAlpcDisconnect (
    IN PUA_SERVER Server
)
{
    NTSTATUS Status;
    PALPC_CONTEXT_ATTR ContextAttribute;
    PPORT_CONTEXT PortContext;

    ContextAttribute = AlpcGetMessageAttribute(Server->MessageAttributes,
                                               ALPC_MESSAGE_CONTEXT_ATTRIBUTE);

    if (NULL == ContextAttribute) {
        return STATUS_UNSUCCESSFUL;
    }

    PortContext = ContextAttribute->PortContext;

    Status = NtClose(PortContext->CommunicationPortHandle);

    UaFreeHeap(PortContext);

    return Status;
}

NTSTATUS
NTAPI
UaAlpcConnect (
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

            if (FALSE == NT_SUCCESS (Status)) {
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

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
UaProcessMessage (
    IN PUA_SERVER Server
)
{
    NTSTATUS Status;

    switch (LOBYTE(Server->PortMessage->u2.s2.Type)) {
    case LPC_REQUEST:
        Status = UaAlpcRequest(Server);
        break;
    case LPC_DATAGRAM:
        Status = UaAlpcDatagram(Server);
        break;
    case LPC_PORT_CLOSED:
        Status = UaAlpcDisconnect(Server);
        break;
    case LPC_CLIENT_DIED:
        Status = UaAlpcDisconnect(Server);
        break;
    case LPC_CONNECTION_REQUEST:
        Status = UaAlpcConnect(Server);
        break;
    default:
        Status = STATUS_SUCCESS;
        break;
    }

    return Status;
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
        BufferLength = ALPC_MAX_ALLOWED_MESSAGE_LENGTH;

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

        Status = UaProcessMessage(Server);

        if (FALSE == NT_SUCCESS(Status)) {
            break;
        }
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

    Server->PortMessage = UaAllocateZeroHeap(ALPC_MAX_ALLOWED_MESSAGE_LENGTH);

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

    Status = RtCreateThread(&Server->ServerThreadHandle,
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
UaSendSynchronousRequest (
    IN HANDLE CommunicationPortHandle,
    IN PVOID RequestDataBuffer,
    IN USHORT RequestDataLength,
    OUT PVOID ReceiveDataBuffer,
    IN USHORT ReceiveDataLength,
    OUT PUSHORT NumberOfBytesReceive
)
{
    NTSTATUS Status;
    USHORT TotalLength;
    PPORT_MESSAGE PortMessage;
    PVOID DataBuffer;
    SIZE_T BufferLength;

    TotalLength = sizeof(PORT_MESSAGE) + MAX(RequestDataLength, ReceiveDataLength);

    if (TotalLength > ALPC_MAX_ALLOWED_MESSAGE_LENGTH) {
        return STATUS_BUFFER_OVERFLOW;
    }

    PortMessage = UaAllocateZeroHeap(TotalLength);

    if (NULL == PortMessage) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PortMessage->u1.s1.TotalLength = TotalLength;
    PortMessage->u1.s1.DataLength = RequestDataLength;

    DataBuffer = PortMessage + 1;
    RtlCopyMemory(DataBuffer, RequestDataBuffer, RequestDataLength);

    BufferLength = TotalLength;
    
    Status = NtAlpcSendWaitReceivePort(CommunicationPortHandle,
                                       ALPC_MSGFLG_SYNC_REQUEST,
                                       PortMessage,
                                       NULL,
                                       PortMessage,
                                       &BufferLength,
                                       NULL,
                                       NULL);

    *NumberOfBytesReceive = PortMessage->u1.s1.DataLength;
    RtlCopyMemory(ReceiveDataBuffer, DataBuffer, PortMessage->u1.s1.DataLength);

    UaFreeHeap(PortMessage);

    return Status;
}

NTSTATUS
NTAPI
UaSendDatagram (
    IN HANDLE CommunicationPortHandle,
    IN PVOID DatagramBuffer,
    IN USHORT DatagramLength
)
{
    NTSTATUS Status;
    USHORT TotalLength;
    PPORT_MESSAGE PortMessage;
    PVOID DataBuffer;

    TotalLength = sizeof(PORT_MESSAGE) + DatagramLength;

    if (TotalLength > ALPC_MAX_ALLOWED_MESSAGE_LENGTH) {
        return STATUS_BUFFER_OVERFLOW;
    }

    PortMessage = UaAllocateZeroHeap(TotalLength);

    if (NULL == PortMessage) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PortMessage->u1.s1.TotalLength = TotalLength;
    PortMessage->u1.s1.DataLength = DatagramLength;

    DataBuffer = PortMessage + 1;

    RtlCopyMemory(DataBuffer, DatagramBuffer, DatagramLength);

    Status = NtAlpcSendWaitReceivePort(CommunicationPortHandle,
                                       ALPC_MSGFLG_RELEASE_MESSAGE,
                                       PortMessage,
                                       NULL,
                                       NULL,
                                       NULL,
                                       NULL,
                                       NULL);

    UaFreeHeap(PortMessage);

    return Status;
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
    SIZE_T BufferLength;
    USHORT TotalLength;
    PPORT_MESSAGE PortMessage;
    PVOID DataBuffer;
    OBJECT_ATTRIBUTES ObjectAttributes;
    ALPC_PORT_ATTRIBUTES PortAttributes;

    TotalLength = sizeof(PORT_MESSAGE) + ConnectionDataLength;

    if (TotalLength > ALPC_MAX_ALLOWED_MESSAGE_LENGTH) {
        return STATUS_BUFFER_OVERFLOW;
    }

    PortMessage = UaAllocateZeroHeap(TotalLength);

    if (NULL == PortMessage) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PortMessage->u1.s1.TotalLength = TotalLength;
    PortMessage->u1.s1.DataLength = ConnectionDataLength;

    DataBuffer = PortMessage + 1;

    RtlCopyMemory(DataBuffer, ConnectionDataBuffer, ConnectionDataLength);

    InitializeObjectAttributes(&ObjectAttributes,
                               NULL,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    UaInitializePortAttributes(&PortAttributes);

    BufferLength = ALPC_MAX_ALLOWED_MESSAGE_LENGTH;

    Status = NtAlpcConnectPort(CommunicationPortHandle,
                               ServerPortName,
                               &ObjectAttributes,
                               &PortAttributes,
                               ALPC_MSGFLG_SYNC_REQUEST,
                               NULL,
                               PortMessage,
                               &BufferLength,
                               NULL,
                               NULL,
                               NULL);

    UaFreeHeap(PortMessage);

    return Status;
}
