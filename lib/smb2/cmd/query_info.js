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
import fs from 'node:fs'

const logger = baseLogger.child({ module: 'smb' })

function dateToWindowsFileTime(date) {
  // Get the time in milliseconds since January 1, 1970 (Unix Epoch)
  const milliseconds = date.getTime()

  // Convert to Windows FILETIME (100-nanosecond intervals since January 1, 1601)
  const windowsFileTime = milliseconds * 10000 + 116444736000000000

  return windowsFileTime
}

/**
 * SMB2_NEGOTIATE (0x0000): Negotiate protocol dialect.
 *
 * @param {Object} msg - an SMB message object
 * @param {Number} commandId - the command id
 * @param {Buffer} body - the command specific message body
 * @param {Object} related - context for related operations (null for unrelated operation)
 * @param {Long} related.sessionId - sessionId
 * @param {Number} related.treeId - treeId
 * @param {Object} related.fileId - fileId
 * @param {Object} connection - an SMBConnection instance
 * @param {Object} server - an SMBServer instance
 * @param {Function} cb callback called with the command's result
 * @param {Object} cb.result - an object with the command's result
 *                             or null if the handler already sent the response and
 *                             no further processing is required by the caller
 * @param {Number} cb.result.status
 * @param {Buffer} cb.result.body
 */
function handle(msg, commandId, body, related, connection, server, cb) {
  if (body.length < 9) {
    throw new Error('Invalid QUERY_INFO packet header')
  }

  const req = binary
    .parse(body)
    .word16le('structureSize')
    .word8('infoType')
    .word8('fileInfoClass')
    .word32le('outputBufferLength')
    .word16le('inputBufferOffset')
    .skip(2) // reserved
    .word32le('inputBufferLength')
    .word32le('additionalInformation')
    .word32le('flags')
    .buffer('fileId', 16).vars

  console.log('QUERY_INFO', req)

  // FileSystem && FileFsSizeInformation
  if (req.infoType === 0x2 && req.fileInfoClass === 0x3) {
    msg.header.treeId = 0x60d1e5f1

    const stat = fs.statfsSync('.')

    const outputBuffer = put()
      .word64le(stat.blocks) // total allocation units
      .word64le(stat.bavail) // available allocation units
      .word32le(stat.bsize / 512) // sectors per allocation unit
      .word32le(512) // bytes per sector
      .buffer()

    const res = put()
      .word16le(9) // StructureSize
      .word16le(outputBuffer ? SMB2.HEADER_LENGTH + 8 : 0) // outputBufferOffset
      .word32le(outputBuffer.length) // outputBufferLength
      .put(outputBuffer)
      .buffer()

    process.nextTick(function () {
      cb({
        status: ntstatus.STATUS_SUCCESS,
        body: res,
      })
    })
    return
  }

  // File && FileNetworkOpenInformation
  if (req.infoType === 0x1 && req.fileInfoClass === 0x22) {
    msg.header.treeId = 0x60d1e5f1

    const stat = fs.statSync('.')
    const dir = stat.isDirectory()

    const outputBuffer = put()
      .word64le(dateToWindowsFileTime(stat.birthtime)) // creationTime
      .word64le(dateToWindowsFileTime(stat.atime)) // lastAccessTime
      .word64le(dateToWindowsFileTime(stat.mtime)) // lastWriteTime
      .word64le(dateToWindowsFileTime(stat.ctime)) // changeTime
      .word64le(dir ? 0 : stat.blksize * stat.blocks) // AllocationSize
      .word64le(dir ? 0 : stat.size) // EndofFile
      .word32le(dir ? 0x1 | 0x10 : 0x1) // FileAttributes
      .pad(4) // Reserved
      .buffer()

    const res = put()
      .word16le(9) // StructureSize
      .word16le(outputBuffer ? SMB2.HEADER_LENGTH + 8 : 0) // outputBufferOffset
      .word32le(outputBuffer.length) // outputBufferLength
      .put(outputBuffer)
      .buffer()

    process.nextTick(function () {
      cb({
        status: ntstatus.STATUS_SUCCESS,
        body: res,
      })
    })
    return
  }

  process.nextTick(function () {
    cb({
      status: ntstatus.STATUS_NOT_SUPPORTED,
      body: put()
        .word16le(0x0009) // StructureSize (fixed according to spec)
        .word8(0) // ErrorContextCount
        .pad(1) // Reserved
        .word32le(0) // ByteCount
        .word8(0) // ErrorData,
        .buffer(),
    })
  })
}

export default handle
