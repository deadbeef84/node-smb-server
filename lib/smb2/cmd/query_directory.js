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

export default async function handle(msg, related, connection, server) {
  if (msg.body.length < 9) {
    throw new Error('Invalid QUERY_DIRECTORY packet header')
  }

  const req = binary
    .parse(msg.body)
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
    // ...req,
    fileName,
  })

  if (req.flags & 0x1) {
    // reopen...
    connection.query = 0
  }

  if (fileName === '*' && req.fileInformationClass === 0x25) {
    msg.header.treeId = 0x60d1e5f1
    // const fileId = Buffer.from('aa'.repeat(8), 'hex');

    if (connection.query) {
      return {
        status: ntstatus.STATUS_NO_MORE_FILES,
        body: put()
          .word16le(0x0009) // StructureSize (fixed according to spec)
          .word8(0) // ErrorContextCount
          .pad(1) // Reserved
          .word32le(0) // ByteCount
          .word8(0) // ErrorData,
          .buffer(),
      }
    }

    connection.query = 1

    // console.log('STAT', stat);

    const files = ['.', '..', ...fs.readdirSync('.')]

    let outputBuffer = Buffer.alloc(0)

    for (const file of files) {
      const name = Buffer.from(file, 'utf16le')
      const stat = fs.statSync(file)
      const dir = stat.isDirectory()
      const buf = put()
        .word32le(0) // nextEntryOffset
        .word32le(0) // fileIndex
        .word64le(dateToWindowsFileTime(stat.birthtime)) // creationTime
        .word64le(dateToWindowsFileTime(stat.atime)) // lastAccessTime
        .word64le(dateToWindowsFileTime(stat.mtime)) // lastWriteTime
        .word64le(dateToWindowsFileTime(stat.ctime)) // changeTime
        .word64le(dir ? 0 : stat.size) // EndofFile
        .word64le(dir ? 0 : stat.blksize * stat.blocks) // AllocationSize
        .word32le(dir ? 0x1 | 0x10 : 0x1) // FileAttributes
        .word32le(name.length) // FileNameLength
        .word32le(0) // EaSize
        .word8(0) // shortNameLength
        .pad(1) // Reserved
        .pad(24) // ShortName
        .pad(2) // Reserved2
        .word64le(0) // FileId
        .put(name) // FileName
        .buffer()

      let pad = 0
      if (file !== files.at(-1)) {
        // not last...
        const paddedLength = Math.ceil(buf.length / 8) * 8
        buf.writeUInt32LE(paddedLength, 0)
        pad = paddedLength - buf.length
      }

      outputBuffer = Buffer.concat([outputBuffer, buf, Buffer.alloc(pad, 0)])
    }

    console.assert(outputBuffer.length <= req.outputBufferLength)

    const res = put()
      .word16le(9) // StructureSize
      .word16le(outputBuffer ? SMB2.HEADER_LENGTH + 8 : 0) // outputBufferOffset
      .word32le(outputBuffer.length) // outputBufferLength
      .put(outputBuffer)
      .buffer()

    return {
      status: ntstatus.STATUS_SUCCESS,
      body: res,
    }
  }

  return {
    status: ntstatus.STATUS_NOT_IMPLEMENTED,
    body: put()
      .word16le(0x0009) // StructureSize (fixed according to spec)
      .word8(0) // ErrorContextCount
      .pad(1) // Reserved
      .word32le(0) // ByteCount
      .word8(0) // ErrorData,
      .buffer(),
  }
}
