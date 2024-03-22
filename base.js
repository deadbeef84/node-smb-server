export class SMB {
  // A Boolean that, if set, indicates that this node requires that messages MUST be signed if the message is sent with a user security context that is neither anonymous nor guest. If not set, this node does not require that any messages be signed, but can still choose to do so if the other node requires it.
  RequireMessageSigning = true

  // A Boolean; if set, indicates that encryption is supported by the node.
  IsEncryptionSupported = false

  // A Boolean; if set, indicates that compression is supported by the node.
  IsCompressionSupported = false

  // A Boolean; if set, indicates that chained compression is supported.
  IsChainedCompressionSupported = false

  // A Boolean; if set, indicates that RDMA transform is supported.
  IsRDMATransformSupported = false

  // A Boolean that, if set, indicates that SMB2 encryption is disabled over a secure transport like QUIC.
  DisableEncryptionOverSecureTransport = true
}

export class SMBServer {
  // Server statistical information. This contains all the members of STAT_SRV_0 structure as specified in [MS-SRVS] section 2.2.4.39.
  ServerStatistics

  // A Boolean that indicates whether the SMB2 server is accepting incoming connections or requests.
  ServerEnabled

  // A list of available shares for the system. The structure of a share is as specified in section 3.3.1.6 and is uniquely indexed by the tuple <Share.ServerName, Share.Name>.
  ShareList

  // A table containing all the files opened by remote clients on the server, indexed by  DurableFileId. The structure of an open is as specified in section 3.3.1.10. The table MUST support enumeration of all entries in the table.
  GlobalOpenTable

  // A list of all the active sessions established to this server, indexed by the Session.SessionId.
  GlobalSessionTable

  // A list of all open connections on the server, indexed by the connection endpoint addresses.
  ConnectionList

  // A global identifier for this server.
  ServerGuid

  // The start time of the SMB2 server, in FILETIME format as specified in [MS-DTYP] section 2.3.3.
  ServerStartTime

  // A Boolean that, if set, indicates that the server supports the Distributed File System.
  IsDfsCapable

  // The maximum number of chunks the server will accept in a server side copy operation.
  ServerSideCopyMaxNumberofChunks

  // The maximum number of bytes the server will accept in a single chunk for a server side copy operation.
  ServerSideCopyMaxChunkSize

  // The maximum total number of bytes the server will accept for a server side copy operation.
  ServerSideCopyMaxDataSize

  // If the server implements the SMB 2.1 or SMB 3.x dialect family, it MUST implement the following:

  // A state that indicates the caching level configured on the server. It takes any of the following three values:
  ServerHashLevel

  // Indicates that caching is enabled for all shares on the server.
  HashEnableAll

  // Indicates that caching is disabled for all shares on the server.
  HashDisableAll

  // Indicates that caching is enabled or disabled on a per-share basis.
  HashEnableShare


  // If the server implements the SMB 2.1 or SMB 3.x dialect family and supports leasing, it MUST implement the following:

  // A list of all the lease tables as described in 3.3.1.11, indexed by the ClientGuid.
  GlobalLeaseTableList


  // If the server implements the SMB 2.1 or SMB 3.x dialect family and supports resiliency, it MUST implement the following:

  // The maximum resiliency time-out in milliseconds, for the Timeout field of NETWORK_RESILIENCY_REQUEST Request, as specified in section 2.2.31.3.
  MaxResiliencyTimeout

  // The time at which the Resilient Open Scavenger Timer, as specified in section 3.3.2.4, is currently set to expire.
  ResilientOpenScavengerExpiryTime


  // If the server implements the SMB 3.x dialect family, it MUST implement the following:

  // A list of clients, indexed by the ClientGuid as specified in section 3.3.1.16.
  GlobalClientTable

  // A Boolean that, if set, indicates that the server requires messages to be encrypted after session establishment, per the conditions specified in section 3.3.5.2.9.
  EncryptData

  // A Boolean that, if set, indicates that the server will reject any unencrypted messages. This flag is applicable only if EncryptData is TRUE or if Share.EncryptData (as defined in section 3.3.1.6) is TRUE.
  RejectUnencryptedAccess

  // A Boolean that, if set, indicates that the server supports the multichannel capability.
  IsMultiChannelCapable

  // A Boolean that, if set, indicates that the server allows anonymous access to named pipes and shares.
  AllowAnonymousAccess

  // If the server implements the SMB 3.0.2 or SMB 3.1.1 dialect, it MUST implement the following:

  // A Boolean that, if set, indicates that the server supports shared virtual disks.
  IsSharedVHDSupported


  // If the server implements the SMB 3.1.1 dialect, it MUST implement the following:

  // The maximum SMB dialect at which clients can access clustered shares on the server.
  MaxClusterDialect

  // A Boolean that, if set, indicates that the server supports the SMB2 TREE_CONNECT Request Extension.
  SupportsTreeConnectExtn

  // A Boolean that, if set, indicates that the server allows opening named pipe when the connection is over QUIC.
  AllowNamedPipeAccessOverQUIC

  // A Boolean that, if set, the server requires mutual authentication to connect to a client over QUIC transport.
  IsMutualAuthOverQUICSupported

  // A table of certificate mapping entries, as specified in section 3.3.1.17, indexed by client name.
  ServerCertificateMappingTable
}

export class Share {
  // A name for the shared resource on this server.
  Name

  // The NetBIOS, fully qualified domain name (FQDN), or textual IPv4 or IPv6 address that the share is associated with. For more information, see [MS-SRVS] section 3.1.1.7.
  ServerName

  // A path that describes the local resource that is being shared. This MUST be a store that either provides named pipe functionality, or that offers storage and/or retrieval of files. In the case of the latter, it MAY<204> be a device that accepts a file and then processes it in some format, such as a printer.
  LocalPath

  // An authorization policy such as an access control list that describes which users are allowed to connect to this share.
  ConnectSecurity

  // An authorization policy such as an access control list that describes what actions users that connect to this share are allowed to perform on the shared resource.<205>
  FileSecurity

  // The configured offline caching policy for this share. This value MUST be manual caching, automatic caching of files, automatic caching of files and programs, or no offline caching. For more information, see section 2.2.10. For more information about offline caching, see [OFFLINE].
  CscFlags

  // A Boolean that, if set, indicates that this share is configured for DFS. For more information, see [MSDFS].
  IsDfs

  // A Boolean that, if set, indicates that the results of directory enumerations on this share MUST be trimmed to include only the files and directories that the calling user has the right to access.
  DoAccessBasedDirectoryEnumeration

  // A Boolean that, if set, indicates that clients are allowed to cache directory enumeration results for better performance.<206>
  AllowNamespaceCaching

  // A Boolean that, if set, indicates that all opens on this share MUST include FILE_SHARE_DELETE in the sharing access.
  ForceSharedDelete

  // A Boolean that, if set, indicates that users who request read-only access to a file are not allowed to deny other readers.
  RestrictExclusiveOpens

  // The value indicates the type of share. It MUST be one of the values that are listed in [MS-SRVS] section 2.2.2.4.
  Type

  // A null-terminated Unicode UTF-16 string that specifies an optional comment about the shared resource.
  Remark

  // The value indicates the maximum number of concurrent connections that the shared resource can accommodate.
  MaxUses

  // The value indicates the number of current trees connected to the shared resource.
  CurrentUses

  // A Boolean that, if set, indicates that the server does not issue exclusive caching rights on this share.
  ForceLevel2Oplock

  // A Boolean that, if set, indicates that the share supports hash generation for branch cache retrieval of data.
  HashEnabled

  // The list of available snapshots in this Share.
  SnapshotList


  // If the server implements the SMB 3.x dialect family, it MUST implement the following:

  // The minimum time, in milliseconds, before closing an unreclaimed persistent handle on a continuously available share.
  CATimeout

  // A Boolean that, if set, indicates that the share is continuously available.
  IsCA

  // A Boolean that, if set, indicates that the server requires messages for accessing this share to be encrypted, per the conditions specified in section 3.3.5.2.11.
  EncryptData

  // A Boolean that, if set, indicates that the share supports identity remoting by the client.
  SupportsIdentityRemoting


  // If the server implements the SMB 3.1.1 dialect, it MUST implement the following:

  // A Boolean that, if set, indicates that the server supports compressed read/write messages for accessing this share.
  CompressData

  // A Boolean that, if set, indicates that the share on the server supports isolated transport.
  IsolatedTransport
}

export class Connection {
  //  A list of the sequence numbers that is valid to receive from the client at this time. For more information, see section 3.3.1.1.
  CommandSequenceWindow

  // A list of requests, as specified in section 3.3.1.13, that are currently being processed by the server. This list is indexed by the MessageId field.
  RequestList

  // The capabilities of the client of this connection in a form that MUST follow the syntax as specified in section 2.2.3.
  ClientCapabilities

  // A numeric value representing the current state of dialect negotiation between the client and server on this transport connection.
  NegotiateDialect

  // A list of client requests being handled asynchronously. Each request MUST have been assigned an AsyncId.
  AsyncCommandList

  // The dialect of SMB2 negotiated with the client. This value MUST be either "2.0.2", "2.1", "3.0", "3.0.2", "3.1.1", or "Unknown". For the purpose of generalization in the server processing rules, the condition that Connection.Dialect is equal to "3.0", "3.0.2", or "3.1.1" is referred to as "Connection.Dialect belongs to the SMB 3.x dialect family".
  Dialect

  // A Boolean that, if set, indicates that all sessions on this connection (with the exception of anonymous and guest sessions) MUST have signing enabled.
  ShouldSign

  // A null-terminated Unicode UTF-16 IP address string, or NetBIOS host name of the client machine.
  ClientName

  // The maximum buffer size, in bytes, that the server allows on the transport that established this connection for QUERY_INFO, QUERY_DIRECTORY, SET_INFO and CHANGE_NOTIFY operations. This field is applicable only for buffers sent by the client in SET_INFO requests, or returned from the server in QUERY_INFO, QUERY_DIRECTORY, and CHANGE_NOTIFY responses.
  MaxTransactSize

  // The maximum buffer size, in bytes, that the server allows to be written on the connection using the SMB2 WRITE Request.
  MaxWriteSize

  // The maximum buffer size, in bytes, that the server allows to be read on the connection using the SMB2 READ Request.
  MaxReadSize

  // A Boolean indicating whether the connection supports multi-credit operations.
  SupportsMultiCredit

  // An implementation-specific name of the transport used by this connection.
  TransportName

  // A table of authenticated sessions, as specified in section 3.3.1.8, established on this SMB2 transport connection. The table MUST allow lookup by both Session.SessionId and by the security context of the user that established the connection.
  SessionTable

  // The time when the connection was established.
  CreationTime

  // A table to store preauthentication hash values for session binding, as specified in section 3.3.1.15. The table MUST allow lookup by PreauthSession.SessionId.
  PreauthSessionTable


  // If the server implements the SMB 2.1 or 3.x dialect family, it MUST implement the following:

  // An identifier for the client machine.
  ClientGuid


  // If the server implements the SMB 3.x dialect family, it MUST implement the following:

  // The capabilities sent by the server in the SMB2 NEGOTIATE Response on this connection, in a form that MUST follow the syntax as specified in section 2.2.4.
  ServerCapabilities

  // The security mode sent by the client in the SMB2 NEGOTIATE request on this connection, in a form that MUST follow the syntax as specified in section 2.2.3.
  ClientSecurityMode

  // The security mode received from the server in the SMB2 NEGOTIATE response on this connection, in a form that MUST follow the syntax as specified in section 2.2.4.
  ServerSecurityMode

  // A Boolean that, if set, indicates that authentication to a non-anonymous principal has not yet been successfully performed on this connection.
  ConstrainedConnection

  // A Boolean indicating whether the server supports one-way notifications on this connection.
  SupportsNotifications


  // If the server implements the SMB 3.1.1 dialect, it MUST also implement the following:

  // The ID of the preauthentication integrity hash function that was negotiated for this connection.
  PreauthIntegrityHashId

  // The preauthentication integrity hash value that was computed for the exchange of SMB2 NEGOTIATE request and response messages on this connection.
  PreauthIntegrityHashValue

  // The ID of the cipher that was negotiated for this connection.
  CipherId

  // An array of dialects received in the SMB2 NEGOTIATE Request on this connection.
  ClientDialects

  // A list of compression algorithm identifiers, if any, used for this connection. Valid values are specified in section 2.2.3.1.3.
  CompressionIds

  // A Boolean that, if set, indicates that chained compression is supported on this connection.
  SupportsChainedCompression

  // A list of RDMA transform identifiers, if any, used for this connection. Valid values are specified in section 2.2.3.1.6.
  RDMATransformIds

  // An identifier of the signing algorithm that was negotiated for this connection.
  SigningAlgorithmId

  // A Boolean that, if set, indicates that transport security is enabled and SMB2 encryption is disabled.
  AcceptTransportSecurity

  // A certificate mapping entry, as specified in section 3.3.1.17, that is used in QUIC connection establishment.
  ServerCertificateMappingEntry
}

export class Session {
  // A numeric value that is used as an index in GlobalSessionTable, and (transformed into a 64-bit number) is sent to clients as the SessionId in the SMB2 header.
  SessionId

  // The current activity state of this session. This value MUST be either InProgress, Valid, or Expired.
  State

  // The security context of the user that authenticated this session. This value MUST be in a form that allows for evaluating security descriptors within the server, as well as being passed to the underlying object store to handle security evaluation that can happen there.
  SecurityContext

  // A Boolean that, if set, indicates that the session is for an anonymous user.
  IsAnonymous

  // A Boolean that, if set, indicates that the session is for a guest user.
  IsGuest

  // The first 16 bytes of the cryptographic key for this authenticated context. If the cryptographic key is less than 16 bytes, it is right-padded with zero bytes.
  SessionKey

  // A Boolean that, if set, indicates that all of the messages for this session MUST be signed.
  SigningRequired

  // A table of opens of files or named pipes, as specified in section 3.3.1.10, that have been opened by this authenticated session and indexed by   FileId. The server MUST support enumeration of all entries in the table.
  OpenTable

  // A table of tree connects that have been established by this authenticated session to shares on this server, indexed by TreeConnect.TreeId. The server MUST allow enumeration of all entries in the table.
  TreeConnectTable

  // A value that specifies the time after which the client MUST reauthenticate with the server.
  ExpirationTime

  // The connection on which this session was established (see also section 3.3.5.5.1).
  Connection

  // A numeric 32-bit value obtained via registration with [MS-SRVS], as specified in [MS-SRVS] section 3.1.6.2.
  SessionGlobalId

  // The time the session was established.
  CreationTime

  // The time the session processed its most recent request.
  IdleTime

  // The name of the user who established the session.
  UserName


  // If the server implements the SMB 3.x dialect family, it MUST implement the following:

  // A list of channels that have been established on this authenticated session, as specified in section 3.3.1.14.
  ChannelList

  // A Boolean that, if set, indicates that the messages on this session SHOULD be encrypted.
  EncryptData

  // For AES-128-CCM and AES-128-GCM encryption algorithms, this is a 128-bit key used for encrypting the messages. For AES-256-CCM and AES-256-GCM encryption algorithms, this is a 256-bit key used for encrypting the messages.
  EncryptionKey

  // For AES-128-CCM and AES-128-GCM encryption algorithms, this is a 128-bit key used for decrypting the messages. For AES-256-CCM and AES-256-GCM encryption algorithms, this is a 256-bit key used for decrypting the messages.
  DecryptionKey

  // A 128 bit key used for signing the SMB2 messages.
  SigningKey

  // A 128-bit key, for the authenticated context, that is queried by the higher-layer applications.
  ApplicationKey

  // A Boolean that, if set, indicates the session supports one-way notifications, which is used to check against subsequent connections in multiple binding requests.
  SupportsNotification


  // If the server implements the SMB 3.1.1 dialect, it MUST also implement the following:

  // The preauthentication integrity hash value that was computed for the exchange of SMB2 SESSION_SETUP request and response messages for this session.
  PreauthIntegrityHashValue

  // Cryptographic key for this authenticated context as returned by underlying authentication protocol.
  FullSessionKey
}

export class TreeConnect {
  // A numeric value that uniquely identifies a tree connect within the scope of the session over which it was established. This value is represented as a 32-bit TreeId in the SMB2 header. 0xFFFFFFFF(-1) MUST be considered as a reserved and invalid value for the TreeId.
  TreeId

  // The authenticated session that established this tree connect.
  Session

  // The share that this tree connect was established for.
  Share

  // A numeric value that indicates the number of files that are currently opened on TreeConnect.
  OpenCount

  // A numeric value obtained via registration with [MS-SRVS], as specified in [MS-SRVS] section 3.1.6.6.
  TreeGlobalId

  // The time tree connect was established.
  CreationTime

  // Access rights for the user that established the tree connect on TreeConnect.Share, in the format specified in section 2.2.13.1.
  MaximalAccess

  // The remoted identity security context of the caller optionally provided by the client via the remoted identity tree connect context.
  RemotedIdentitySecurityContext
}

export class Open {
  // A numeric value that uniquely identifies the open handle to a file or a pipe within the scope of a session over which the handle was opened. A 64-bit representation of this value, combined with  DurableFileId as described below, form the SMB2_FILEID described in section 2.2.14.1.
  FileId

  // A numeric value obtained via registration with [MS-SRVS], as specified in [MS-SRVS] section 3.1.6.4.
  FileGlobalId

  // A numeric value that uniquely identifies the open handle to a file or a pipe within the scope of all opens granted by the server, as described by the GlobalOpenTable. A 64-bit representation of this value combined with   FileId, as described above, form the SMB2_FILEID described in section 2.2.14.1. This value is the persistent portion of the identifier.
  DurableFileId

  // A reference to the authenticated session, as specified in section 3.3.1.8, over which this open was performed. If the open is not attached to a session at this time, this value MUST be NULL.
  Session

  // A reference to the TreeConnect, as specified in section 3.3.1.9, over which the open was performed. If the open is not attached to a TreeConnect at this time, this value MUST be NULL.
  TreeConnect

  // A reference to the connection, as specified in section 3.3.1.7, that created this open. If the open is not attached to a connection at this time, this value MUST be NULL.
  Connection

  // An open of a file or named pipe in the underlying local resource that is used to perform the local operations, such as reading or writing, to the underlying object. For named pipes,  LocalOpen is shared between the SMB server and RPC server applications which serve RPC requests on a given named pipe. The higher level interfaces described in sections 3.3.4.5 and 3.3.4.11 require this shared element.
  LocalOpen

  // The access granted on this open, as defined in section 2.2.13.1.
  GrantedAccess

  // The current oplock level for this open. This value MUST be one of the OplockLevel values defined in section 2.2.14SMB2_OPLOCK_LEVEL_NONE, SMB2_OPLOCK_LEVEL_II, SMB2_OPLOCK_LEVEL_EXCLUSIVE, SMB2_OPLOCK_LEVEL_BATCH, or SMB2_OPLOCK_LEVEL_LEASE.
  OplockLevel

  // The current oplock state of the file. This value MUST be Held, Breaking, or None.
  OplockState

  // The time value that indicates when an oplock that is breaking and has not received an acknowledgment from the client will be acknowledged by the server.
  OplockTimeout

  // A Boolean that indicates whether the Open is preserved for reconnect.
  IsDurable

  // The time the server waits before closing a handle that has been preserved for durability, if a client has not reclaimed it.
  DurableOpenTimeout

  // A time stamp value, if non-zero, representing the maximum time to preserve the open for reclaim.
  DurableOpenScavengerTimeout

  // A security descriptor that holds the original opener of the open. This allows the server to determine if a caller that is trying to reestablish a durable open is allowed to do so. If the server implements SMB 2.1 or SMB 3.x and supports resiliency, this value is also used to enforce security during resilient open reestablishment.
  DurableOwner

  // For extended attribute information, this value indicates the current location in an extended attribute information list and allows for the continuing of an enumeration across multiple requests.
  CurrentEaIndex

  // For quota queries, this value indicates the current index in the quota information list and allows for the continuation of an enumeration across multiple requests.
  CurrentQuotaIndex

  // A numeric value that indicates the number of locks that are held by current open.
  LockCount

  // A variable-length Unicode string that contains the local path name on the server that the open is performed on.
  PathName

  // A 24-byte key that identifies a source file in a server-side data copy operation.
  ResumeKey

  // A Unicode file name supplied by the client for this
  FileName

  // The create options requested by the client for this Open, in the format specified in section 2.2.13.
  CreateOptions

  // The file attributes used by the client for this Open, in the format specified in section 2.2.13.
  FileAttributes


  // If the server supports leasing, it MUST implement the following:

  // An identifier for the client machine that created this open.
  ClientGuid

  // The lease associated with this open, as defined in 3.3.1.12. This value MUST point to a valid lease, or be set to NULL.
  Lease


  // If the server supports resiliency, it MUST implement the following:

  // A Boolean that indicates whether this open has requested resilient operation.
  IsResilient

  // A time-out value that indicates how long the server will hold the file open after a disconnect before releasing the open.
  ResiliencyTimeout

  // A time-out value that indicates when a handle that has been preserved for resiliency will be closed by the system if a client has not reclaimed it.
  ResilientOpenTimeout

  // An array of 64 entries used to maintain lock sequences for resilient opens. Each entry MUST be assigned an index from the range of 1 to 64. Each entry is a structure with the following elements:
  LockSequenceArray

  // A 4-bit integer modulo 16.
  SequenceNumber

  // A Boolean, if set to TRUE, indicates that the SequenceNumber element is valid.
  Valid


  // If the server implements the SMB 3.x dialect family, it MUST implement the following:

  // A 16-byte value that associates this open to a create request.
  CreateGuid

  // A 16-byte value that associates this open with a calling application.
  AppInstanceId

  // A Boolean that indicates whether this open is persistent.
  IsPersistent

  // A 16-bit identifier indicating the client's Channel change.
  ChannelSequence

  // A numerical value that indicates the number of outstanding requests issued with ChannelSequence equal to   ChannelSequence.
  OutstandingRequestCount

  // A numerical value that indicates the number of outstanding requests issued with ChannelSequence less than  ChannelSequence.
  OutstandingPreRequestCount

  // A Boolean that indicates whether the Open is eligible for replay by a CREATE request that can be replayed by reissuing the original CREATE request with the SMB2_FLAGS_REPLAY_OPERATION flag set.
  IsReplayEligible


  // If the server implements the SMB 3.0.2 or SMB 3.1.1 dialect, it MUST implement the following:

  // A Boolean that indicates whether this open is a shared virtual disk operation.
  IsSharedVHDX


  // If the server implements the SMB 3.1.1 dialect, it MUST implement the following:

  // An unsigned 64-bit numeric value representing the most significant value of the application instance version.
  ApplicationInstanceVersionHigh

  // An unsigned 64-bit numeric value representing the least significant value of the application instance version.
  ApplicationInstanceVersionLow
}

export class Request {
  // The value of the MessageId field from the SMB2 Header of the client request.
  MessageId

  // An asynchronous identifier generated for an Asynchronous Operation, as specified in section 3.3.4.2. The identifier MUST uniquely identify this Request among all requests currently being processed asynchronously on a specified SMB2 transport connection. If the request is not being processed asynchronously, this value MUST be set to zero.
  AsyncId

  // An implementation-dependent identifier generated by the server to support cancellation of pending requests that are sent to the object store. The identifier MUST be unique among all requests currently being processed by the server and all object store operations being performed by other server applications.<207>
  CancelRequestId

  // A reference to an Open of a file or named pipe, as specified in section 3.3.1.10. If the request is not associated with an Open at this time, this value MUST be NULL.
  Open


  // If the server implements the SMB 3.x dialect family, it MUST implement the following:

  // A Boolean that, if set, indicates that the request has been encrypted.
  IsEncrypted

  // The SessionId sent by the client in the SMB2 TRANSFORM_HEADER, if the request is encrypted.
  TransformSessionId


  // If the server implements the SMB 3.1.1 dialect, it implements the following:

  // A Boolean that, if set, indicates that the reply to this request is eligible for compression.
  CompressReply
}

