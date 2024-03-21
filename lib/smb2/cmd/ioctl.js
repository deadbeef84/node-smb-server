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

import put from 'put'

import binary from 'binary'
import baseLogger from '../../logger.js'

import ntstatus from '../../ntstatus.js'
const logger = baseLogger.child({ module: 'smb' })

const FSCTL_DFS_GET_REFERRALS = 0x00060194 // SMB2-specific processing
const FSCTL_DFS_GET_REFERRALS_EX = 0x000601b0 // SMB2-specific processing
const FSCTL_IS_PATHNAME_VALID = 0x0009002c
const FSCTL_GET_COMPRESSION = 0x0009003c
const FSCTL_FILESYSTEM_GET_STATISTICS = 0x00090060
const FSCTL_QUERY_FAT_BPB = 0x00090058
const FSCTL_GET_NTFS_VOLUME_DATA = 0x00090064
const FSCTL_GET_RETRIEVAL_POINTERS = 0x00090073
const FSCTL_FIND_FILES_BY_SID = 0x0009008f
const FSCTL_SET_OBJECT_ID = 0x00090098
const FSCTL_GET_OBJECT_ID = 0x0009009c
const FSCTL_DELETE_OBJECT_ID = 0x000900a0
const FSCTL_SET_REPARSE_POINT = 0x000900a4 // SMB2-specific processing
const FSCTL_GET_REPARSE_POINT = 0x000900a8
const FSCTL_DELETE_REPARSE_POINT = 0x000900ac
const FSCTL_SET_OBJECT_ID_EXTENDED = 0x000900bc
const FSCTL_CREATE_OR_GET_OBJECT_ID = 0x000900c0
const FSCTL_SET_SPARSE = 0x000900c4
const FSCTL_READ_FILE_USN_DATA = 0x000900eb
const FSCTL_WRITE_USN_CLOSE_RECORD = 0x000900ef
const FSCTL_QUERY_SPARING_INFO = 0x00090138
const FSCTL_QUERY_ON_DISK_VOLUME_INFO = 0x0009013c
const FSCTL_SET_ZERO_ON_DEALLOCATION = 0x00090194
const FSCTL_QUERY_FILE_REGIONS = 0x00090284
const FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT = 0x00090300
const FSCTL_SVHDX_SYNC_TUNNEL_REQUEST = 0x00090304
const FSCTL_STORAGE_QOS_CONTROL = 0x00090350
const FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST = 0x00090364
const FSCTL_QUERY_ALLOCATED_RANGES = 0x000940cf
const FSCTL_OFFLOAD_READ = 0x00094264
const FSCTL_SET_ZERO_DATA = 0x000980c8
const FSCTL_SET_DEFECT_MANAGEMENT = 0x00098134
const FSCTL_FILE_LEVEL_TRIM = 0x00098208 // SMB2-specific processing
const FSCTL_OFFLOAD_WRITE = 0x00098268
const FSCTL_DUPLICATE_EXTENTS_TO_FILE = 0x00098344
const FSCTL_SET_COMPRESSION = 0x0009c040
const FSCTL_PIPE_WAIT = 0x00110018 // SMB2-specific processing
const FSCTL_PIPE_PEEK = 0x0011400c // SMB2-specific processing
const FSCTL_PIPE_TRANSCEIVE = 0x0011c017 // SMB2-specific processing
const FSCTL_SRV_REQUEST_RESUME_KEY = 0x00140078 // SMB2-specific processing
const FSCTL_LMR_SET_LINK_TRACKING_INFORMATION = 0x001400ec
const FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204 // SMB2-specific processing
const FSCTL_LMR_REQUEST_RESILIENCY = 0x001401d4 // SMB2-specific processing
const FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401fc // SMB2-specific processing
const FSCTL_SRV_ENUMERATE_SNAPSHOTS = 0x00144064 // SMB2-specific processing
const FSCTL_SRV_COPYCHUNK = 0x001440f2 // SMB2-specific processing
const FSCTL_SRV_READ_HASH = 0x001441bb // SMB2-specific processing
const FSCTL_SRV_COPYCHUNK_WRITE = 0x001480f2 // SMB2-specific processing

export default async function handle(msg, related, connection, server) {
  if (msg.body.length < 9) {
    throw new Error('Invalid IOCTL packet header')
  }

  const req = binary
    .parse(msg.body)
    .word16lu('structureSize')
    .skip(2) // reserved
    .word32le('ctlCode')
    .buffer('fileId', 16)
    .word32le('inputOffset')
    .word32le('inputCount')
    .word32le('maxInputResponse')
    .word32le('outputOffset')
    .word32le('outputCount')
    .word32le('maxOutputResponse')
    .word32le('flags')
    .word32le('reserved2').vars

  const inputStart = 56 + req.inputOffset
  const input = msg.body.slice(inputStart, inputStart + req.inputCount)
  const outputStart = 56 + req.outputOffset
  const output = msg.body.slice(outputStart, outputStart + req.outputCount)

  console.log('IOCTL', { ...req, input, output })

  if (!(req.flags & 0x1)) {
    return {
      status: ntstatus.STATUS_NOT_SUPPORTED,
    }
  }

  if (req.ctlCode === FSCTL_DFS_GET_REFERRALS || req.ctlCode === FSCTL_DFS_GET_REFERRALS_EX) {
    // [MS-SMB2] 3.3.5.15.2 Handling a DFS Referral Information Request
    // state.LogToServer(Severity.Verbose, "IOCTL failed. CTL Code: {0}. NTStatus: STATUS_FS_DRIVER_REQUIRED.", ctlCode);
    return {
      status: ntstatus.STATUS_FS_DRIVER_REQUIRED,
    }
  }

  let handle = null
  if (
    req.ctlCode === FSCTL_PIPE_WAIT ||
    req.ctlCode === FSCTL_VALIDATE_NEGOTIATE_INFO ||
    req.ctlCode === FSCTL_QUERY_NETWORK_INTERFACE_INFO
  ) {
    // [MS-SMB2] 3.3.5.15 - FSCTL_PIPE_WAIT / FSCTL_QUERY_NETWORK_INTERFACE_INFO /
    // FSCTL_VALIDATE_NEGOTIATE_INFO requests MUST have FileId set to 0xFFFFFFFFFFFFFFFF.
    if (!req.fileId.equals(Buffer.from('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 'hex'))) {
      // state.LogToServer(Severity.Verbose, "IOCTL failed. CTL Code: {0}. FileId MUST be 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", ctlCode);
      return {
        status: ntstatus.STATUS_INVALID_PARAMETER,
      }
    }
    handle = null
  } else {
    /*
    let openFile = session.GetOpenFileObject(req.fileId);
    if (openFile == null) {
      // state.LogToServer(Severity.Verbose, "IOCTL failed. CTL Code: {0}. Invalid FileId. (SessionID: {1}, TreeID: {2}, FileId: {3})", ctlCode, request.Header.SessionID, request.Header.TreeID, req.fileId.Volatile);
      return {
        status: ntstatus.STATUS_FILE_CLOSED,
      }
    }
    handle = openFile.Handle;
    */
  }

  return {
    status: ntstatus.STATUS_NOT_SUPPORTED,
  }

  /*
  let res = put()
    .word16le(49) // StructureSize
    .word16le(0) // reserved
    .word32le(0) // CtlCode
    .buffer();

  msg.header.treeId = 0x60d1e5f1;
  // msg.header.flags.priorityMask = true

  // return result

  process.nextTick(function () {
    cb(result);
  });
  */
}
