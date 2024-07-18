#ifndef _ALPC_H_
#define _ALPC_H_

EXTERN_C_START

typedef struct _PORT_CONTEXT {
    CLIENT_ID ClientId;
    HANDLE CommunicationPortHandle;
} PORT_CONTEXT, *PPORT_CONTEXT;

typedef
VOID
(NTAPI *REQUEST_PROCEDURE)(
    IN OUT PPORT_MESSAGE PortMessage
    );

typedef
VOID
(NTAPI *DATAGRAM_PROCEDURE)(
    IN PPORT_MESSAGE PortMessage
    );

typedef
BOOLEAN
(NTAPI *CONNECTION_PROCEDURE)(
    IN PPORT_MESSAGE PortMessage
    );

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

VOID
NTAPI
UaTerminateServer (
    IN PUA_SERVER ServerObject
);

PUA_SERVER
NTAPI
UaCreateServer (
    IN PUNICODE_STRING ServerPortName,
    IN REQUEST_PROCEDURE OnRequest,
    IN DATAGRAM_PROCEDURE OnDatagram,
    IN CONNECTION_PROCEDURE OnConnect
);

NTSTATUS
NTAPI
UaSendSynchronousRequest (
    IN HANDLE CommunicationPortHandle,
    IN PVOID RequestDataBuffer,
    IN ULONG RequestDataLength,
    OUT PVOID ResponseDataBuffer,
    IN ULONG ResponseDataLength,
    OUT PULONG NumberOfBytesResponse
);

NTSTATUS
NTAPI
UaSendDatagram (
    IN HANDLE CommunicationPortHandle,
    IN PVOID DatagramDataBuffer OPTIONAL,
    IN ULONG DatagramDataLength
);

VOID
NTAPI
UaDisconnectServer (
    IN HANDLE CommunicationPortHandle
);

NTSTATUS
NTAPI
UaConnectServer (
    OUT PHANDLE CommunicationPortHandle,
    IN PUNICODE_STRING ServerPortName,
    IN PVOID ConnectionDataBuffer OPTIONAL,
    IN USHORT ConnectionDataLength
);

EXTERN_C_END

#endif
