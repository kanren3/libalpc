#ifndef _ALPC_H_
#define _ALPC_H_

EXTERN_C_START

typedef struct _UA_SERVER *PUA_SERVER;

typedef
NTSTATUS
(NTAPI *REQUEST_PROCEDURE)(
    IN PCLIENT_ID ClientId,
    IN OUT PVOID ShareBuffer,
    IN ULONG RequestBufferLength,
    IN ULONG ResponseBufferLength,
    OUT PULONG NumberOfResponse
    );

typedef
VOID
(NTAPI *DATAGRAM_PROCEDURE)(
    IN PCLIENT_ID ClientId,
    IN PVOID DatagramBuffer,
    IN ULONG DatagramBufferLength
    );

typedef
BOOLEAN
(NTAPI *CONNECTION_PROCEDURE)(
    IN PCLIENT_ID ClientId,
    IN PVOID ConnectionBuffer,
    IN USHORT ConnectionBufferLength
    );

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
    IN PVOID RequestBuffer,
    IN ULONG RequestBufferLength,
    OUT PVOID ResponseBuffer,
    IN ULONG ResponseBufferLength,
    OUT PULONG NumberOfResponse OPTIONAL,
    OUT PNTSTATUS ResponseStatus OPTIONAL
);

NTSTATUS
NTAPI
UaSendDatagram (
    IN HANDLE CommunicationPortHandle,
    IN PVOID DatagramBuffer OPTIONAL,
    IN ULONG DatagramBufferLength
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
    IN PVOID ConnectionBuffer OPTIONAL,
    IN USHORT ConnectionBufferLength
);

EXTERN_C_END

#endif
