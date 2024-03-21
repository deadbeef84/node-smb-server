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

const { FILE_READ_ATTRIBUTES, FILE_LIST_DIRECTORY } = require('../../smb/constants')

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
  if (body.length < 4) {
    throw new Error('Invalid TREE_DISCONNECT packet header')
  }

  const req = binary.parse(body).word16lu('structureSize').vars

  console.log('TREE_DISCONNECT', req)

  const res = put()
    .word16le(4) // StructureSize
    .word16le(0) // Reserved
    .buffer()

  msg.header.treeId = 0x60d1e5f1
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

module.exports = handle
