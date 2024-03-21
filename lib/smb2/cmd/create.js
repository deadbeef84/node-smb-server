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
import SMB2 from '../constants.js'
import * as utils from '../../utils.js'
import fs from 'node:fs'
const logger = baseLogger.child({ module: 'smb' })

function dateToWindowsFileTime(date) {
  // Get the time in milliseconds since January 1, 1970 (Unix Epoch)
  const milliseconds = date.getTime()

  // Convert to Windows FILETIME (100-nanosecond intervals since January 1, 1601)
  const windowsFileTime = milliseconds * 10000 + 116444736000000000

  return windowsFileTime
}

export default async function handle(msg, related, connection, server) {
  if (msg.body.length < 9) {
    throw new Error('Invalid TREE_CONNECT packet header')
  }

  const req = binary
    .parse(msg.body)
    .word16lu('structureSize')
    .skip(1) // reserved
    .word8('reqOplockLevel')
    .word32le('impersonationLevel')
    .word64le('createFlags')
    .skip(8)
    .word32le('desiredAccess')
    .word32le('fileAttributes')
    .word32le('shareAccess')
    .word32le('createDisposition')
    .word32le('createOptions')
    .word16le('nameOffset')
    .word16le('nameLength')
    .word32le('createContextOffset')
    .word32le('createContextLength').vars

  const name = msg.buf.subarray(req.nameOffset, req.nameOffset + req.nameLength).toString('utf16le')

  console.log('CREATE', {
    ...req,
    name,
  })

  if (name === '') {
    msg.header.treeId = 0x60d1e5f1
    const fileId = Buffer.from('aa'.repeat(16), 'hex')

    const stat = fs.statSync('.')
    console.log('STAT', stat)

    const res = put()
      .word16le(89) // StructureSize
      .word8(0) // oplockLevel
      .word8(0) // flags
      .word32le(1) // createAction
      .word64le(dateToWindowsFileTime(stat.birthtime)) // creationTime
      .word64le(dateToWindowsFileTime(stat.atime)) // lastAccessTime
      .word64le(dateToWindowsFileTime(stat.mtime)) // lastWriteTime
      .word64le(dateToWindowsFileTime(stat.ctime)) // changeTime
      .word64le(0) // AllocationSize
      .word64le(0) // EndofFile
      .word32le(0x1 | 0x10) // FileAttributes
      .pad(4) // Reserved2
      .put(fileId) // 16 bytes, fileId
      .word32le(0) // CreateContextsOffset
      .word32le(0) // CreateContextLength
      .buffer()

    return {
      status: ntstatus.STATUS_SUCCESS,
      body: res,
    }
  }

  // return result
  return {
    status: ntstatus.STATUS_NOT_IMPLEMENTED,
  }
}
