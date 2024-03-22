export const AccessMask = {
  // The bits in positions 16 through 31 are object specific.
  DELETE: 0x00010000,
  READ_CONTROL: 0x00020000,
  WRITE_DAC: 0x00040000,
  WRITE_OWNER: 0x00080000,
  SYNCHRONIZE: 0x00100000,
  ACCESS_SYSTEM_SECURITY: 0x01000000,
  MAXIMUM_ALLOWED: 0x02000000,
  GENERIC_ALL: 0x10000000,
  GENERIC_EXECUTE: 0x20000000,
  GENERIC_WRITE: 0x40000000,
  GENERIC_READ: 0x80000000,
}

export const DirectoryAccessMask = {
  FILE_LIST_DIRECTORY: 0x00000001,
  FILE_ADD_FILE: 0x00000002,
  FILE_ADD_SUBDIRECTORY: 0x00000004,
  FILE_READ_EA: 0x00000008,
  FILE_WRITE_EA: 0x00000010,
  FILE_TRAVERSE: 0x00000020,
  FILE_DELETE_CHILD: 0x00000040,
  FILE_READ_ATTRIBUTES: 0x00000080,
  FILE_WRITE_ATTRIBUTES: 0x00000100,
  DELETE: 0x00010000,
  READ_CONTROL: 0x00020000,
  WRITE_DAC: 0x00040000,
  WRITE_OWNER: 0x00080000,
  SYNCHRONIZE: 0x00100000,
  ACCESS_SYSTEM_SECURITY: 0x01000000,
  MAXIMUM_ALLOWED: 0x02000000,
  GENERIC_ALL: 0x10000000,
  GENERIC_EXECUTE: 0x20000000,
  GENERIC_WRITE: 0x40000000,
  GENERIC_READ: 0x80000000,
}

export const FileAccessMask = {
  FILE_READ_DATA: 0x00000001,
  FILE_WRITE_DATA: 0x00000002,
  FILE_APPEND_DATA: 0x00000004,
  FILE_READ_EA: 0x00000008,
  FILE_WRITE_EA: 0x00000010,
  FILE_EXECUTE: 0x00000020,
  FILE_READ_ATTRIBUTES: 0x00000080,
  FILE_WRITE_ATTRIBUTES: 0x00000100,
  DELETE: 0x00010000,
  READ_CONTROL: 0x00020000,
  WRITE_DAC: 0x00040000,
  WRITE_OWNER: 0x00080000,
  SYNCHRONIZE: 0x00100000,
  ACCESS_SYSTEM_SECURITY: 0x01000000,
  MAXIMUM_ALLOWED: 0x02000000,
  GENERIC_ALL: 0x10000000,
  GENERIC_EXECUTE: 0x20000000,
  GENERIC_WRITE: 0x40000000,
  GENERIC_READ: 0x80000000,
}

export const CompressionFormat = {
  COMPRESSION_FORMAT_NONE: 0x0000,
  COMPRESSION_FORMAT_DEFAULT: 0x0001,
  COMPRESSION_FORMAT_LZNT1: 0x0002,
}

export const ExtendedAttributeFlags = {
  FILE_NEED_EA: 0x80,
}

export const FileAttributes = {
  ReadOnly: 0x00000001, // FILE_ATTRIBUTE_READONLY
  Hidden: 0x00000002, // FILE_ATTRIBUTE_HIDDEN
  System: 0x00000004, // FILE_ATTRIBUTE_SYSTEM
  Directory: 0x00000010, // FILE_ATTRIBUTE_DIRECTORY
  Archive: 0x00000020, // FILE_ATTRIBUTE_ARCHIVE

  /// <summary>
  /// A file that does not have other attributes set.
  /// This attribute is valid only when used alone.
  /// </summary>
  Normal: 0x00000080, // FILE_ATTRIBUTE_NORMAL
  Temporary: 0x00000100, // FILE_ATTRIBUTE_TEMPORARY
  SparseFile: 0x00000200, // FILE_ATTRIBUTE_SPARSE_FILE
  ReparsePoint: 0x00000400, // FILE_ATTRIBUTE_REPARSE_POINT
  Compressed: 0x00000800, // FILE_ATTRIBUTE_COMPRESSED
  Offline: 0x00001000, // FILE_ATTRIBUTE_OFFLINE
  NotContentIndexed: 0x00002000, // FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
  Encrypted: 0x00004000, // FILE_ATTRIBUTE_ENCRYPTED
  IntegrityStream: 0x00008000, // FILE_ATTRIBUTE_INTEGRITY_STREAM
  NoScrubData: 0x00020000, // FILE_ATTRIBUTE_NO_SCRUB_DATA
}

export const FileInformationClass = {
  FileDirectoryInformation: 0x01, // Uses: Query
  FileFullDirectoryInformation: 0x02, // Uses: Query
  FileBothDirectoryInformation: 0x03, // Uses: Query
  FileBasicInformation: 0x04, // Uses: Query, Set
  FileStandardInformation: 0x05, // Uses: Query
  FileInternalInformation: 0x06, // Uses: Query
  FileEaInformation: 0x07, // Uses: Query
  FileAccessInformation: 0x08, // Uses: Query
  FileNameInformation: 0x09, // Uses: LOCAL
  FileRenameInformation: 0x0a, // Uses: Set
  FileLinkInformation: 0x0b, // Uses: Set
  FileNamesInformation: 0x0c, // Uses: Query
  FileDispositionInformation: 0x0d, // Uses: Set
  FilePositionInformation: 0x0e, // Uses: Query, Set
  FileFullEaInformation: 0x0f, // Uses: Query, Set
  FileModeInformation: 0x10, // Uses: Query, Set
  FileAlignmentInformation: 0x11, // Uses: Query
  FileAllInformation: 0x12, // Uses: Query
  FileAllocationInformation: 0x13, // Uses: Set
  FileEndOfFileInformation: 0x14, // Uses: Set
  FileAlternateNameInformation: 0x15, // Uses: Query
  FileStreamInformation: 0x16, // Uses: Query
  FilePipeInformation: 0x17, // Uses: Query, Set
  FilePipeLocalInformation: 0x18, // Uses: Query
  FilePipeRemoteInformation: 0x19, // Uses: Query
  FileCompressionInformation: 0x1c, // Uses: Query
  FileNetworkOpenInformation: 0x22, // Uses: Query
  FileAttributeTagInformation: 0x23, // Uses: Query
  FileIdBothDirectoryInformation: 0x25, // Uses: Query
  FileIdFullDirectoryInformation: 0x26, // Uses: Query
  FileValidDataLengthInformation: 0x27, // Uses: Set
  FileShortNameInformation: 0x28, // Uses: Set
}

export const DeviceCharacteristics = {
  RemovableMedia: 0x0001, // FILE_REMOVABLE_MEDIA
  ReadOnlyDevice: 0x0002, // FILE_READ_ONLY_DEVICE
  FloppyDiskette: 0x0004, // FILE_FLOPPY_DISKETTE
  WriteOnceMedia: 0x0008, // FILE_WRITE_ONCE_MEDIA
  RemoteDevice: 0x0010, // FILE_REMOTE_DEVICE
  IsMounted: 0x0020, // FILE_DEVICE_IS_MOUNTED
  VirtualVolume: 0x0040, // FILE_VIRTUAL_VOLUME
}

export const DeviceType = {
  Beep: 0x0001, // FILE_DEVICE_BEEP
  CDRom: 0x0002, // FILE_DEVICE_CD_ROM
  CDRomFileSystem: 0x0003, // FILE_DEVICE_CD_ROM_FILE_SYSTEM
  Controller: 0x0004, // FILE_DEVICE_CONTROLLER
  DataLink: 0x0005, // FILE_DEVICE_DATALINK
  DFS: 0x0006, // FILE_DEVICE_DFS
  Disk: 0x0007, // FILE_DEVICE_DISK
  DiskFileSystem: 0x0008, // FILE_DEVICE_DISK_FILE_SYSTEM
  FileSystem: 0x0009, // FILE_DEVICE_FILE_SYSTEM
  ImportPort: 0x000a, // FILE_DEVICE_INPORT_PORT
  Keyboard: 0x000b, // FILE_DEVICE_KEYBOARD
  MailSlot: 0x000c, // FILE_DEVICE_MAILSLOT
  MidiIn: 0x000d, // FILE_DEVICE_MIDI_IN
  MidiOut: 0x000e, // FILE_DEVICE_MIDI_OUT
  Mouse: 0x000f, // FILE_DEVICE_MOUSE
  MultiUNCProvider: 0x0010, // FILE_DEVICE_MULTI_UNC_PROVIDER
  NamedPipe: 0x0011, // FILE_DEVICE_NAMED_PIPE
  Network: 0x0012, // FILE_DEVICE_NETWORK
  NetworkBrowser: 0x0013, // FILE_DEVICE_NETWORK_BROWSER
  NetworkFileSystem: 0x0014, // FILE_DEVICE_NETWORK_FILE_SYSTEM
  Null: 0x0015, // FILE_DEVICE_NULL
  ParallelPort: 0x0016, // FILE_DEVICE_PARALLEL_PORT
  PhysicalNetcard: 0x0017, // FILE_DEVICE_PHYSICAL_NETCARD
  Printer: 0x0018, // FILE_DEVICE_PRINTER
  Scanner: 0x0019, // FILE_DEVICE_SCANNER
  SerialMousePort: 0x001a, // FILE_DEVICE_SERIAL_MOUSE_PORT
  SerialPort: 0x001b, // FILE_DEVICE_SERIAL_PORT
  Screen: 0x001c, // FILE_DEVICE_SCREEN
  Sound: 0x001d, // FILE_DEVICE_SOUND
  Streams: 0x001e, // FILE_DEVICE_STREAMS
  Tape: 0x001f, // FILE_DEVICE_TAPE
  TapeFileSystem: 0x0020, // FILE_DEVICE_TAPE_FILE_SYSTEM
  Transport: 0x0021, // FILE_DEVICE_TRANSPORT
  Unknown: 0x0022, // FILE_DEVICE_UNKNOWN
  Video: 0x0023, // FILE_DEVICE_VIDEO
  VirtualDisk: 0x0024, // FILE_DEVICE_VIRTUAL_DISK
  WaveIn: 0x0025, // FILE_DEVICE_WAVE_IN
  WaveOut: 0x0026, // FILE_DEVICE_WAVE_OUT
  PS2Port: 0x0027, // FILE_DEVICE_8042_PORT
  NetworkRedirector: 0x0028, // FILE_DEVICE_NETWORK_REDIRECTOR
  Battery: 0x0029, // FILE_DEVICE_BATTERY
  BusExtender: 0x002a, // FILE_DEVICE_BUS_EXTENDER
  Modem: 0x002b, // FILE_DEVICE_MODEM
  VirtualDosMachine: 0x002c, // FILE_DEVICE_VDM
}

export const FileSystemAttributes = {
  CaseSensitiveSearch: 0x0001, // FILE_CASE_SENSITIVE_SEARCH
  CasePreservedNamed: 0x0002, // FILE_CASE_PRESERVED_NAMES
  UnicodeOnDisk: 0x0004, // FILE_UNICODE_ON_DISK
  PersistentACLs: 0x0008, // FILE_PERSISTENT_ACLS
  FileCompression: 0x0010, // FILE_FILE_COMPRESSION
  VolumeQuotas: 0x0020, // FILE_VOLUME_QUOTAS
  SupportsSparseFiles: 0x0040, // FILE_SUPPORTS_SPARSE_FILES
  SupportsReparsePoints: 0x0080, // FILE_SUPPORTS_REPARSE_POINTS
  SupportsRemoteStorage: 0x0100, // FILE_SUPPORTS_REMOTE_STORAGE
  VolumeIsCompressed: 0x8000, // FILE_VOLUME_IS_COMPRESSED
  SupportsObjectIDs: 0x00010000, // FILE_SUPPORTS_OBJECT_IDS
  SupportsEncryption: 0x00020000, // FILE_SUPPORTS_ENCRYPTION
  NamedStreams: 0x00040000, // FILE_NAMED_STREAMS
  ReadOnlyVolume: 0x00080000, // FILE_READ_ONLY_VOLUME
  SequentialWriteOnce: 0x00100000, // FILE_SEQUENTIAL_WRITE_ONCE
  SupportsTransactions: 0x00200000, // FILE_SUPPORTS_TRANSACTIONS
  SupportsHardLinks: 0x00400000, // FILE_SUPPORTS_HARD_LINKS
  SupportsExtendedAttributes: 0x00800000, // FILE_SUPPORTS_EXTENDED_ATTRIBUTES
  SupportsOpenByFileID: 0x01000000, // FILE_SUPPORTS_OPEN_BY_FILE_ID
  SupportsUSNJournal: 0x02000000, // FILE_SUPPORTS_USN_JOURNAL
}

export const FileSystemControlFlags = {
  QuotaTrack: 0x00000001, // FILE_VC_QUOTA_TRACK
  QuotaEnforce: 0x00000002, // FILE_VC_QUOTA_ENFORCE
  ContentIndexingDisabled: 0x00000008, // FILE_VC_CONTENT_INDEX_DISABLED
  LogQuotaThreshold: 0x00000010, // FILE_VC_LOG_QUOTA_THRESHOLD
  LogQuotaLimit: 0x00000020, // FILE_VC_LOG_QUOTA_LIMIT
  LogVolumeThreshold: 0x00000040, // FILE_VC_LOG_VOLUME_THRESHOLD
  LogVolumeLimit: 0x00000080, // FILE_VC_LOG_VOLUME_LIMIT
  QuotasIncomplete: 0x00000100, // FILE_VC_QUOTAS_INCOMPLETE
  QuotasRebuilding: 0x00000200, // FILE_VC_QUOTAS_REBUILDING
}

export const FileSystemInformationClass = {
  FileFsVolumeInformation: 0x01, // Uses: Query
  FileFsLabelInformation: 0x02,
  FileFsSizeInformation: 0x03, // Uses: Query
  FileFsDeviceInformation: 0x04, // Uses: Query
  FileFsAttributeInformation: 0x05, // Uses: Query
  FileFsControlInformation: 0x06, // Uses: Query, Set
  FileFsFullSizeInformation: 0x07, // Uses: Query
  FileFsObjectIdInformation: 0x08, // Uses: Query, Set
  FileFsDriverPathInformation: 0x09,
  FileFsVolumeFlagsInformation: 0x0a,
  FileFsSectorSizeInformation: 0x0b, // Uses: Query
}

export const SectorSizeInformationFlags = {
  AlignedDevice: 0x00000001, // SSINFO_FLAGS_ALIGNED_DEVICE
  PartitionAlignedOnDevice: 0x00000002, // SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE
  NoSeekPenalty: 0x0000004, // SSINFO_FLAGS_NO_SEEK_PENALTY
  TrimEnabled: 0x00000008, // SSINFO_FLAGS_TRIM_ENABLED
}

export const CreateDisposition = {
  /// <summary>
  /// If the file already exists, replace it with the given file.
  /// If it does not, create the given file.
  /// </summary>
  FILE_SUPERSEDE: 0x0000,

  /// <summary>
  /// If the file already exists, open it [instead of creating a new file].
  /// If it does not, fail the request [and do not create a new file].
  /// </summary>
  FILE_OPEN: 0x0001,

  /// <summary>
  /// If the file already exists, fail the request [and do not create or open the given file].
  /// If it does not, create the given file.
  /// </summary>
  FILE_CREATE: 0x0002,

  /// <summary>
  /// If the file already exists, open it.
  /// If it does not, create the given file.
  /// </summary>
  FILE_OPEN_IF: 0x0003,

  /// <summary>
  /// If the file already exists, open it and overwrite it.
  /// If it does not, fail the request.
  /// </summary>
  FILE_OVERWRITE: 0x0004,

  /// <summary>
  /// If the file already exists, open it and overwrite it.
  /// If it does not, create the given file.
  /// </summary>
  FILE_OVERWRITE_IF: 0x0005,
}

export const CreateOptions = {
  /// <summary>
  /// The file being created or opened is a directory file.
  /// With this option, the CreateDisposition field MUST be set to FILE_CREATE, FILE_OPEN, or FILE_OPEN_IF.
  /// </summary>
  FILE_DIRECTORY_FILE: 0x00000001,

  /// <summary>
  /// Applications that write data to the file MUST actually transfer the data into the file before any write request is considered complete.
  /// If FILE_NO_INTERMEDIATE_BUFFERING is set, the server MUST perform as if FILE_WRITE_THROUGH is set in the create request.
  /// </summary>
  FILE_WRITE_THROUGH: 0x00000002,

  /// <summary>
  /// This option indicates that access to the file can be sequential.
  /// The server can use this information to influence its caching and read-ahead strategy for this file.
  /// The file MAY in fact be accessed randomly, but the server can optimize its caching and read-ahead policy for sequential access.
  /// </summary>
  FILE_SEQUENTIAL_ONLY: 0x00000004,

  /// <summary>
  /// The file SHOULD NOT be cached or buffered in an internal buffer by the server.
  /// This option is incompatible when the FILE_APPEND_DATA bit field is set in the DesiredAccess field.
  /// </summary>
  FILE_NO_INTERMEDIATE_BUFFERING: 0x00000008,

  FILE_SYNCHRONOUS_IO_ALERT: 0x00000010,

  FILE_SYNCHRONOUS_IO_NONALERT: 0x00000020,

  /// <summary>
  /// If the file being opened is a directory, the server MUST fail the request with STATUS_FILE_IS_A_DIRECTORY
  /// </summary>
  FILE_NON_DIRECTORY_FILE: 0x00000040,

  FILE_CREATE_TREE_CONNECTION: 0x00000080,

  FILE_COMPLETE_IF_OPLOCKED: 0x00000100,

  /// <summary>
  /// The application that initiated the client's request does not support extended attributes (EAs).
  /// If the EAs on an existing file being opened indicate that the caller SHOULD support EAs to correctly interpret the file, the server SHOULD fail this request with STATUS_ACCESS_DENIED.
  /// </summary>
  FILE_NO_EA_KNOWLEDGE: 0x00000200,

  /// <summary>
  /// formerly known as FILE_OPEN_FOR_RECOVERY
  /// </summary>
  FILE_OPEN_REMOTE_INSTANCE: 0x00000400,

  /// <summary>
  /// Indicates that access to the file can be random.
  /// The server MAY use this information to influence its caching and read-ahead strategy for this file.
  /// This is a hint to the server that sequential read-ahead operations might not be appropriate on the file.
  /// </summary>
  FILE_RANDOM_ACCESS: 0x00000800,

  /// <summary>
  /// The file SHOULD be automatically deleted when the last open request on this file is closed.
  /// When this option is set, the DesiredAccess field MUST include the DELETE flag.
  /// This option is often used for temporary files.
  /// </summary>
  FILE_DELETE_ON_CLOSE: 0x00001000,

  /// <summary>
  /// Opens a file based on the FileId.
  /// If this option is set, the server MUST fail the request with STATUS_NOT_SUPPORTED in the Status field of the SMB Header in the server response.
  /// </summary>
  FILE_OPEN_BY_FILE_ID: 0x00002000,

  /// <summary>
  /// The file is being opened or created for the purposes of either a backup or a restore operation.
  /// Thus, the server can make appropriate checks to ensure that the caller is capable of overriding
  /// whatever security checks have been placed on the file to allow a backup or restore operation to occur.
  /// The server can check for certain access rights to the file before checking the DesiredAccess field.
  /// </summary>
  FILE_OPEN_FOR_BACKUP_INTENT: 0x00004000,

  /// <summary>
  /// When a new file is created, the file MUST NOT be compressed, even if it is on a compressed volume.
  /// The flag MUST be ignored when opening an existing file.
  /// </summary>
  FILE_NO_COMPRESSION: 0x00008000,

  FILE_OPEN_REQUIRING_OPLOCK: 0x00010000,

  FILE_DISALLOW_EXCLUSIVE: 0x00020000,

  FILE_RESERVE_OPFILTER: 0x00100000,

  FILE_OPEN_REPARSE_POINT: 0x00200000,

  /// <summary>
  /// In a hierarchical storage management environment, this option requests that the file SHOULD NOT be recalled from tertiary storage such as tape.
  /// A file recall can take up to several minutes in a hierarchical storage management environment.
  /// The clients can specify this option to avoid such delays.
  /// </summary>
  FILE_OPEN_NO_RECALL: 0x00400000,

  FILE_OPEN_FOR_FREE_SPACE_QUERY: 0x00800000,
}

export const FileStatus = {
  FILE_SUPERSEDED: 0x00000000,
  FILE_OPENED: 0x00000001,
  FILE_CREATED: 0x00000002,
  FILE_OVERWRITTEN: 0x00000003,
  FILE_EXISTS: 0x00000004,
  FILE_DOES_NOT_EXIST: 0x00000005,
}

export const ShareAccess = {
  None: 0x00000000, // FILE_SHARE_NONE
  Read: 0x00000001, // FILE_SHARE_READ
  Write: 0x00000002, // FILE_SHARE_WRITE
  Delete: 0x00000004, // FILE_SHARE_DELETE
}

export const ImpersonationLevel = {
  Anonymous: 0x00000000, // SECURITY_ANONYMOUS
  Identification: 0x00000001, // SECURITY_IDENTIFICATION
  Impersonation: 0x00000002, // SECURITY_IMPERSONATION
  Delegation: 0x00000003, // SECURITY_DELEGATION (This impersonation level is supported starting with Windows 2000)
}

export const SecurityInformation = {
  OWNER_SECURITY_INFORMATION: 0x00000001,
  GROUP_SECURITY_INFORMATION: 0x00000002,
  DACL_SECURITY_INFORMATION: 0x00000004,
  SACL_SECURITY_INFORMATION: 0x00000008,
  LABEL_SECURITY_INFORMATION: 0x00000010,
  ATTRIBUTE_SECURITY_INFORMATION: 0x00000020,
  SCOPE_SECURITY_INFORMATION: 0x00000040,
  BACKUP_SECURITY_INFORMATION: 0x00010000,
}

export const IoControlCode = {
  FSCTL_DFS_GET_REFERRALS: 0x00060194, // SMB2-specific processing
  FSCTL_DFS_GET_REFERRALS_EX: 0x000601b0, // SMB2-specific processing
  FSCTL_IS_PATHNAME_VALID: 0x0009002c,
  FSCTL_GET_COMPRESSION: 0x0009003c,
  FSCTL_FILESYSTEM_GET_STATISTICS: 0x00090060,
  FSCTL_QUERY_FAT_BPB: 0x00090058,
  FSCTL_GET_NTFS_VOLUME_DATA: 0x00090064,
  FSCTL_GET_RETRIEVAL_POINTERS: 0x00090073,
  FSCTL_FIND_FILES_BY_SID: 0x0009008f,
  FSCTL_SET_OBJECT_ID: 0x00090098,
  FSCTL_GET_OBJECT_ID: 0x0009009c,
  FSCTL_DELETE_OBJECT_ID: 0x000900a0,
  FSCTL_SET_REPARSE_POINT: 0x000900a4, // SMB2-specific processing
  FSCTL_GET_REPARSE_POINT: 0x000900a8,
  FSCTL_DELETE_REPARSE_POINT: 0x000900ac,
  FSCTL_SET_OBJECT_ID_EXTENDED: 0x000900bc,
  FSCTL_CREATE_OR_GET_OBJECT_ID: 0x000900c0,
  FSCTL_SET_SPARSE: 0x000900c4,
  FSCTL_READ_FILE_USN_DATA: 0x000900eb,
  FSCTL_WRITE_USN_CLOSE_RECORD: 0x000900ef,
  FSCTL_QUERY_SPARING_INFO: 0x00090138,
  FSCTL_QUERY_ON_DISK_VOLUME_INFO: 0x0009013c,
  FSCTL_SET_ZERO_ON_DEALLOCATION: 0x00090194,
  FSCTL_QUERY_FILE_REGIONS: 0x00090284,
  FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT: 0x00090300,
  FSCTL_SVHDX_SYNC_TUNNEL_REQUEST: 0x00090304,
  FSCTL_STORAGE_QOS_CONTROL: 0x00090350,
  FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST: 0x00090364,
  FSCTL_QUERY_ALLOCATED_RANGES: 0x000940cf,
  FSCTL_OFFLOAD_READ: 0x00094264,
  FSCTL_SET_ZERO_DATA: 0x000980c8,
  FSCTL_SET_DEFECT_MANAGEMENT: 0x00098134,
  FSCTL_FILE_LEVEL_TRIM: 0x00098208, // SMB2-specific processing
  FSCTL_OFFLOAD_WRITE: 0x00098268,
  FSCTL_DUPLICATE_EXTENTS_TO_FILE: 0x00098344,
  FSCTL_SET_COMPRESSION: 0x0009c040,
  FSCTL_PIPE_WAIT: 0x00110018, // SMB2-specific processing
  FSCTL_PIPE_PEEK: 0x0011400c, // SMB2-specific processing
  FSCTL_PIPE_TRANSCEIVE: 0x0011c017, // SMB2-specific processing
  FSCTL_SRV_REQUEST_RESUME_KEY: 0x00140078, // SMB2-specific processing
  FSCTL_LMR_SET_LINK_TRACKING_INFORMATION: 0x001400ec,
  FSCTL_VALIDATE_NEGOTIATE_INFO: 0x00140204, // SMB2-specific processing
  FSCTL_LMR_REQUEST_RESILIENCY: 0x001401d4, // SMB2-specific processing
  FSCTL_QUERY_NETWORK_INTERFACE_INFO: 0x001401fc, // SMB2-specific processing
  FSCTL_SRV_ENUMERATE_SNAPSHOTS: 0x00144064, // SMB2-specific processing
  FSCTL_SRV_COPYCHUNK: 0x001440f2, // SMB2-specific processing
  FSCTL_SRV_READ_HASH: 0x001441bb, // SMB2-specific processing
  FSCTL_SRV_COPYCHUNK_WRITE: 0x001480f2, // SMB2-specific processing
}

export const NotifyChangeFilter = {
  FileName: 0x0000001, // FILE_NOTIFY_CHANGE_FILE_NAME
  DirName: 0x0000002, // FILE_NOTIFY_CHANGE_DIR_NAME
  Attributes: 0x0000004, // FILE_NOTIFY_CHANGE_ATTRIBUTES
  Size: 0x0000008, // FILE_NOTIFY_CHANGE_SIZE
  LastWrite: 0x000000010, // FILE_NOTIFY_CHANGE_LAST_WRITE
  LastAccess: 0x00000020, // FILE_NOTIFY_CHANGE_LAST_ACCESS
  Creation: 0x00000040, // FILE_NOTIFY_CHANGE_CREATION
  EA: 0x00000080, // FILE_NOTIFY_CHANGE_EA
  Security: 0x00000100, // FILE_NOTIFY_CHANGE_SECURITY
  StreamName: 0x00000200, // FILE_NOTIFY_CHANGE_STREAM_NAME
  StreamSize: 0x00000400, // FILE_NOTIFY_CHANGE_STREAM_SIZE
  StreamWrite: 0x00000800, // FILE_NOTIFY_CHANGE_STREAM_WRITE
}
