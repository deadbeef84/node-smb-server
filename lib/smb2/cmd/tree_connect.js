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
import consts from '../../smb/constants.js'
const logger = baseLogger.child({ module: 'smb' })
const { FILE_READ_ATTRIBUTES, FILE_LIST_DIRECTORY } = consts

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
    .skip(2) // SMB3 flags, reserved otherwise
    .word16lu('pathOffset')
    .word16lu('pathLength').vars

  const path = msg.buf.subarray(req.pathOffset, req.pathOffset + req.pathLength).toString('utf16le')

  console.log('TREE_CONNECT', req, path)

  const share = path.endsWith('\\IPC$')
    ? {
        type: 2,
        access: 0x001f00a9,
      }
    : {
        type: 1,
        flags: 0x00000010 | 0x00000020 | 0x00000100 | 0x00000200,
        access: FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
      }

  const res = put()
    .word16le(16) // StructureSize
    .word8(share.type) // ShareType
    .word8(0) // Reserved
    .word32le(share.flags ?? 0) // ShareFlags
    .word32le(0) // Capabilities
    .word32le(share.access) // MaximalAccess
    .buffer()

  msg.header.treeId = path.endsWith('IPC$') ? 0x60d1e5f0 : 0x60d1e5f1
  // msg.header.flags.priorityMask = true

  // return result
  const result = {
    status: ntstatus.STATUS_SUCCESS,
    body: res,
  }
  process.nextTick(function () {
    cb(result)
  })
}

export default handle
