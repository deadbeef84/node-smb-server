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
import { GetSPNEGOTokenInitBytes } from '../../gssapi.js'
const logger = baseLogger.child({ module: 'smb' })

export default async function handle(msg, related, connection, server) {
  const dialects = []
  const parser = binary.parse(msg.body)
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
    SMB2.COMMAND_TO_STRING[msg.header.commandId].toUpperCase(),
    dialectsString
  )

  // target SMB 2.1 for now
  let targetDialect
  if (params.dialects.indexOf(SMB2.SMB_2_1_0) > -1) {
    targetDialect = SMB2.SMB_2_1_0
    // targetDialect = SMB2.SMB_3_1_1;
  } else if (params.dialects.indexOf(SMB2.SMB_2_0_2) > -1) {
    targetDialect = SMB2.SMB_2_0_2
  } else {
    return {
      status: ntstatus.STATUS_NOT_IMPLEMENTED,
      body: utils.EMPTY_BUFFER,
    }
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
  return {
    status: ntstatus.STATUS_SUCCESS,
    body: out.buffer(),
  }
}
