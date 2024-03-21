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

const put = require('put')
const binary = require('binary')
const logger = require('winston').loggers.get('smb')

const ntstatus = require('../../ntstatus')
const SMB2 = require('../constants')
const utils = require('../../utils')
const fs = require('fs')

const { FILE_READ_ATTRIBUTES, FILE_LIST_DIRECTORY } = require('../../smb/constants')

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
    throw new Error('Invalid TREE_CONNECT packet header')
  }

  const req = binary
    .parse(body)
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

    process.nextTick(function () {
      cb({
        status: ntstatus.STATUS_SUCCESS,
        body: res,
      })
    })
    return
  }

  // return result
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

module.exports = handle
