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

export default async function handle(msg, related, connection, server) {
  if (msg.body.length < 9) {
    throw new Error('Invalid CLOSE packet header')
  }

  const req = binary
    .parse(msg.body)
    .word16le('structureSize')
    .word16le('flags')
    .word32le('reserved')
    .buffer('fileId', 16).vars

  console.log('CLOSE', req)

  if (req.flags === 0) {
    msg.header.treeId = 0x60d1e5f1
    const res = put()
      .word16le(60) // StructureSize
      .word16le(0) // flags
      .word32le(0) // reserved
      .word64le(0) // creationTime
      .word64le(0) // lastAccessTime
      .word64le(0) // lastWriteTime
      .word64le(0) // changeTime
      .word64le(0) // AllocationSize
      .word64le(0) // EndofFile
      .word32le(0) // FileAttributes
      .buffer()

    return {
      status: ntstatus.STATUS_SUCCESS,
      body: res,
    }
  }

  return {
    status: ntstatus.STATUS_NOT_IMPLEMENTED,
  }
}
