/*
 *  Copyright 2015 Adobe Systems Incorporated. All rights reserved.
 *  This file is licensed to you under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License. You may obtain a copy
 *  of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under
 *  the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
 *  OF ANY KIND, either express or implied. See the License for the specific language
 *  governing permissions and limitations under the License.
 */

import _ from 'lodash'

const consts = {}

/**
 * a selection of 32bit NT Status codes (see [MS-ERREF] 2.3 for complete list)
 */
consts.STATUS_SUCCESS = 0x00000000
consts.STATUS_INVALID_SMB = 0x00010002 // At least one command parameter fails validation tests such as a field value being out of range or fields within a command being internally inconsistent.
consts.STATUS_SMB_BAD_TID = 0x00050002 // The TID specified in the command was invalid.
consts.STATUS_SMB_BAD_FID = 0x00060001 // Invalid FID.
consts.STATUS_SMB_BAD_UID = 0x005b0002 // The UID specified is not known as a valid ID on this server session.
consts.STATUS_SMB_BAD_COMMAND = 0x00160002 // An unknown SMB command code was received by the server.
consts.STATUS_OS2_INVALID_LEVEL = 0x007c0001 // Invalid information level.
consts.STATUS_UNSUCCESSFUL = 0xc0000001 // General error.
consts.STATUS_NOT_IMPLEMENTED = 0xc0000002 // Unrecognized SMB command code.
consts.STATUS_INVALID_HANDLE = 0xc0000008 // Invalid FID.
consts.STATUS_END_OF_FILE = 0xc0000011 // Attempted to read beyond the end of the file..
consts.STATUS_INVALID_PARAMETER = 0xc000000d // A parameter supplied with the message is invalid.
consts.STATUS_NO_SUCH_FILE = 0xc000000f // File not found.
consts.STATUS_MORE_PROCESSING_REQUIRED = 0xc0000016 // There is more data available to read on the designated named pipe.
consts.STATUS_ACCESS_DENIED = 0xc0000022 // Access denied.
consts.STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034 // File not found.
consts.STATUS_OBJECT_NAME_COLLISION = 0xc0000035 // An attempt to create a file or directory failed because an object with the same pathname already exists.
consts.STATUS_OBJECT_PATH_NOT_FOUND = 0xc000003a // File not found.
consts.STATUS_EAS_NOT_SUPPORTED = 0xc000004f // The server file system does not support Extended Attributes.
consts.STATUS_EA_TOO_LARGE = 0xc0000050 // Either there are no extended attributes, or the available extended attributes did not fit into the response.
consts.STATUS_WRONG_PASSWORD = 0xc000006a // Invalid password.
consts.STATUS_LOGON_FAILURE = 0xc000006d
consts.STATUS_IO_TIMEOUT = 0xc00000b5 // Operation timed out.
consts.STATUS_FILE_IS_A_DIRECTORY = 0xc00000ba
consts.STATUS_NOT_SUPPORTED = 0xc00000bb
consts.STATUS_UNEXPECTED_NETWORK_ERROR = 0xc00000c4 // Operation timed out.
consts.STATUS_NETWORK_ACCESS_DENIED = 0xc00000ca // Access denied. The specified UID does not have permission to execute the requested command within the current context (TID).
consts.STATUS_BAD_DEVICE_TYPE = 0xc00000cb // Resource type invalid. Value of Service field in the request was invalid.
consts.STATUS_BAD_NETWORK_NAME = 0xc00000cc // Invalid server name in Tree Connect.
consts.STATUS_TOO_MANY_SESSIONS = 0xc00000ce // Too many UIDs active for this SMB connection.
consts.STATUS_REQUEST_NOT_ACCEPTED = 0xc00000d0 // No resources currently available for this SMB request.
consts.STATUS_NOT_A_DIRECTORY = 0xc0000103
consts.STATUS_SMB_NO_SUPPORT = 0xffff0002 // Function not supported by the server.

consts.STATUS_SUCCESS = 0x00000000
consts.STATUS_PENDING = 0x00000103
consts.STATUS_NOTIFY_CLEANUP = 0x0000010b
consts.STATUS_NOTIFY_ENUM_DIR = 0x0000010c
consts.SEC_I_CONTINUE_NEEDED = 0x00090312
consts.STATUS_OBJECT_NAME_EXISTS = 0x40000000
consts.STATUS_BUFFER_OVERFLOW = 0x80000005
consts.STATUS_NO_MORE_FILES = 0x80000006
consts.SEC_E_SECPKG_NOT_FOUND = 0x80090305
consts.SEC_E_INVALID_TOKEN = 0x80090308
consts.STATUS_NOT_IMPLEMENTED = 0xc0000002
consts.STATUS_INVALID_INFO_CLASS = 0xc0000003
consts.STATUS_INFO_LENGTH_MISMATCH = 0xc0000004
consts.STATUS_INVALID_HANDLE = 0xc0000008
consts.STATUS_INVALID_PARAMETER = 0xc000000d
consts.STATUS_NO_SUCH_DEVICE = 0xc000000e
consts.STATUS_NO_SUCH_FILE = 0xc000000f
consts.STATUS_INVALID_DEVICE_REQUEST = 0xc0000010
consts.STATUS_END_OF_FILE = 0xc0000011
consts.STATUS_MORE_PROCESSING_REQUIRED = 0xc0000016
consts.STATUS_ACCESS_DENIED = 0xc0000022 // The user is not authorized to access the resource.
consts.STATUS_BUFFER_TOO_SMALL = 0xc0000023
consts.STATUS_OBJECT_NAME_INVALID = 0xc0000033
consts.STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034
consts.STATUS_OBJECT_NAME_COLLISION = 0xc0000035 // The file already exists
consts.STATUS_OBJECT_PATH_INVALID = 0xc0000039
consts.STATUS_OBJECT_PATH_NOT_FOUND = 0xc000003a // The share path does not reference a valid resource.
consts.STATUS_OBJECT_PATH_SYNTAX_BAD = 0xc000003b
consts.STATUS_DATA_ERROR = 0xc000003e // IO error
consts.STATUS_SHARING_VIOLATION = 0xc0000043
consts.STATUS_FILE_LOCK_CONFLICT = 0xc0000054
consts.STATUS_LOCK_NOT_GRANTED = 0xc0000055
consts.STATUS_DELETE_PENDING = 0xc0000056
consts.STATUS_PRIVILEGE_NOT_HELD = 0xc0000061
consts.STATUS_WRONG_PASSWORD = 0xc000006a
consts.STATUS_LOGON_FAILURE = 0xc000006d // Authentication failure.
consts.STATUS_ACCOUNT_RESTRICTION = 0xc000006e // The user has an empty password, which is not allowed
consts.STATUS_INVALID_LOGON_HOURS = 0xc000006f
consts.STATUS_INVALID_WORKSTATION = 0xc0000070
consts.STATUS_PASSWORD_EXPIRED = 0xc0000071
consts.STATUS_ACCOUNT_DISABLED = 0xc0000072
consts.STATUS_RANGE_NOT_LOCKED = 0xc000007e
consts.STATUS_DISK_FULL = 0xc000007f
consts.STATUS_INSUFFICIENT_RESOURCES = 0xc000009a
consts.STATUS_MEDIA_WRITE_PROTECTED = 0xc00000a2
consts.STATUS_FILE_IS_A_DIRECTORY = 0xc00000ba
consts.STATUS_NOT_SUPPORTED = 0xc00000bb
consts.STATUS_NETWORK_NAME_DELETED = 0xc00000c9
consts.STATUS_BAD_DEVICE_TYPE = 0xc00000cb
consts.STATUS_BAD_NETWORK_NAME = 0xc00000cc
consts.STATUS_TOO_MANY_SESSIONS = 0xc00000ce
consts.STATUS_REQUEST_NOT_ACCEPTED = 0xc00000d0
consts.STATUS_DIRECTORY_NOT_EMPTY = 0xc0000101
consts.STATUS_NOT_A_DIRECTORY = 0xc0000103
consts.STATUS_TOO_MANY_OPENED_FILES = 0xc000011f
consts.STATUS_CANCELLED = 0xc0000120
consts.STATUS_CANNOT_DELETE = 0xc0000121
consts.STATUS_FILE_CLOSED = 0xc0000128
consts.STATUS_LOGON_TYPE_NOT_GRANTED = 0xc000015b
consts.STATUS_ACCOUNT_EXPIRED = 0xc0000193
consts.STATUS_FS_DRIVER_REQUIRED = 0xc000019c
consts.STATUS_USER_SESSION_DELETED = 0xc0000203
consts.STATUS_INSUFF_SERVER_RESOURCES = 0xc0000205
consts.STATUS_PASSWORD_MUST_CHANGE = 0xc0000224
consts.STATUS_NOT_FOUND = 0xc0000225
consts.STATUS_ACCOUNT_LOCKED_OUT = 0xc0000234
consts.STATUS_PATH_NOT_COVERED = 0xc0000257
consts.STATUS_NOT_A_REPARSE_POINT = 0xc0000275

consts.STATUS_INVALID_SMB = 0x00010002 // SMB1/CIFS: A corrupt or invalid SMB request was received
consts.STATUS_SMB_BAD_COMMAND = 0x00160002 // SMB1/CIFS: An unknown SMB command code was received by the server
consts.STATUS_SMB_BAD_FID = 0x00060001 // SMB1/CIFS
consts.STATUS_SMB_BAD_TID = 0x00050002 // SMB1/CIFS
consts.STATUS_OS2_INVALID_ACCESS = 0x000c0001 // SMB1/CIFS
consts.STATUS_OS2_NO_MORE_SIDS = 0x00710001 // SMB1/CIFS
consts.STATUS_OS2_INVALID_LEVEL = 0x007c0001 // SMB1/CIFS

consts.STATUS_TO_STRING = _.reduce(
  consts,
  function (result, val, nm) {
    if (nm.indexOf('STATUS_') === 0) {
      result[val] = nm
    }
    return result
  },
  {}
)

export default consts
