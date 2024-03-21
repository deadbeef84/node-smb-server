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
const { GetSPNEGOTokenInitBytes } = require('../../gssapi')

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
  const parser = binary.parse(body)
  const dialects = []
  const params = parser
    .word16le('structureSize') // 0x0024 (fixed according to spec)
    .word16le('dialectCount')
    .word16le('securityMode')
    .skip(2) // Reserved
    .word32le('capabilities')
    .buffer('clientGuid', 16)
    .word32le('negotiateContextOffset')
    .word16le('negotiateContextCount')
    .skip(2) // Reserved2
    .buffer('dialectsRaw', 2 * parser.vars.dialectCount).vars

  let off = 0
  params.dialects = []
  let dialectsString = ''
  while (params.dialects.length < params.dialectCount) {
    const dialectCode = params.dialectsRaw.readUInt16LE(off)
    off += 2
    params.dialects.push(dialectCode)
    if (dialectsString !== '') {
      dialectsString += ', '
    }
    dialectsString += '0x' + dialectCode.toString(16)
  }

  logger.debug(
    '[%s] dialects: [ %s ]',
    SMB2.COMMAND_TO_STRING[commandId].toUpperCase(),
    dialectsString
  )

  let result

  // target SMB 2.1 for now
  let targetDialect
  if (params.dialects.indexOf(SMB2.SMB_2_1_0) > -1) {
    targetDialect = SMB2.SMB_2_1_0
    // targetDialect = SMB2.SMB_3_1_1;
  } else if (params.dialects.indexOf(SMB2.SMB_2_0_2) > -1) {
    targetDialect = SMB2.SMB_2_0_2
  } else {
    result = {
      status: ntstatus.STATUS_NOT_IMPLEMENTED,
      body: utils.EMPTY_BUFFER,
    }
    process.nextTick(function () {
      cb(result)
    })
  }

  const systemTime = utils.systemToSMBTime(Date.now())
  const startTime = utils.systemToSMBTime(server.getStartTime())
  const securityBuffer = GetSPNEGOTokenInitBytes()
  const out = put()
  out
    .word16le(0x0041) // StructureSize (fixed according to spec)
    .word16le(0) // SecurityMode
    .word16le(targetDialect) // DialectRevision
    .word16le(3) // NegotiateContextCount/Reserved
    .put(server.getGuid()) // ServerGuid
    .word32le(SMB2.GLOBAL_CAP_DFS | SMB2.GLOBAL_CAP_LARGE_MTU) // Capabilities
    .word32le(0x00100000) // MaxTransactSize
    .word32le(0x00100000) // MaxReadSize
    .word32le(0x00100000) // MaxWriteSize
    .word32le(systemTime.getLowBitsUnsigned()) // SystemTime
    .word32le(systemTime.getHighBitsUnsigned())
    .word32le(startTime.getLowBitsUnsigned()) // ServerStartTime
    .word32le(startTime.getHighBitsUnsigned())
    .word16le(SMB2.HEADER_LENGTH + 64) // SecurityBufferOffset
    .word16le(securityBuffer.length) // SecurityBufferLength
    .word32le(SMB2.HEADER_LENGTH + 64 + securityBuffer.length + 6) // NegotiateContextOffset/Reserved2
    .put(securityBuffer) // SecurityBuffer
    .put(
      Buffer.concat([
        Buffer.alloc(6, 0),
        // Negotiate Context: SMB2_PREAUTH_INTEGRITY_CAPABILITIES
        Buffer.from(
          '01002600000000000100200001001fc8040723b018a22509a84d9d6936475e18402583d6567efc004535ef9a2ddc',
          'hex'
        ),
        Buffer.alloc(2, 0),
        // Negotiate Context: SMB2_ENCRYPTION_CAPABILITIES
        Buffer.from('020004000000000001000200', 'hex'),
        Buffer.alloc(4, 0),
        // Negotiate Context: SMB2_SIGNING_CAPABILITIES
        Buffer.from('080004000000000001000200', 'hex'),
      ])
    )

  // return result
  result = {
    status: ntstatus.STATUS_SUCCESS,
    body: out.buffer(),
  }
  process.nextTick(function () {
    cb(result)
  })
}

module.exports = handle
