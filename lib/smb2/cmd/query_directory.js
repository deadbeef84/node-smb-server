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
    throw new Error('Invalid QUERY_DIRECTORY packet header')
  }

  const req = binary
    .parse(body)
    .word16le('structureSize')
    .word8('fileInformationClass')
    .word8('flags')
    .word32le('fileIndex')
    .buffer('fileId', 16)
    .word16le('fileNameOffset')
    .word16le('fileNameLength')
    .word32le('outputBufferLength').vars

  const fileName = req.fileNameOffset
    ? msg.buf
        .subarray(req.fileNameOffset, req.fileNameOffset + req.fileNameLength)
        .toString('utf16le')
    : null

  console.log('QUERY_DIRECTORY', {
    ...req,
    fileName,
  })

  if (fileName === '*' && req.fileInformationClass === 0x25) {
    msg.header.treeId = 0x60d1e5f1
    // let fileId = Buffer.from('aa'.repeat(8), 'hex');

    if (connection.query) {
      process.nextTick(function () {
        cb({
          status: ntstatus.STATUS_NO_MORE_FILES,
          body: put()
            .word16le(0x0009) // StructureSize (fixed according to spec)
            .word8(0) // ErrorContextCount
            .pad(1) // Reserved
            .word32le(0) // ByteCount
            .word8(0) // ErrorData,
            .buffer(),
        })
      })
      return
    }

    connection.query = 1

    const stat = fs.statSync('.')
    console.log('STAT', stat)

    const name = Buffer.from('.', 'utf16le')
    const shortName = Buffer.from('', 'utf16le')

    const outputBuffer = put()
      .word32le(0) // nextEntryOffset
      .word32le(0) // fileIndex
      .word64le(dateToWindowsFileTime(stat.birthtime)) // creationTime
      .word64le(dateToWindowsFileTime(stat.atime)) // lastAccessTime
      .word64le(dateToWindowsFileTime(stat.mtime)) // lastWriteTime
      .word64le(dateToWindowsFileTime(stat.ctime)) // changeTime
      .word64le(0) // EndofFile
      .word64le(0) // AllocationSize
      .word32le(0x1 | 0x10) // FileAttributes
      .word32le(name.length) // FileNameLength
      .word32le(0) // EaSize
      .word8(shortName.length) // shortNameLength
      .pad(1) // Reserved
      .pad(24) // ShortName
      .pad(2) // Reserved2
      .word64le(0) // FileId
      .put(name) // FileName
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
      status: ntstatus.STATUS_NOT_IMPLEMENTED,
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
