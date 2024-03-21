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
import crypto from 'node:crypto'
import baseLogger from '../../logger.js'

import ntstatus from '../../ntstatus.js'
import SMB2 from '../constants.js'
import { AcceptSecurityContext } from '../../gssapi.js'
const logger = baseLogger.child({ module: 'smb' })

export default async function handle(msg, related, connection, server) {
  if (msg.body.length < 64) {
    throw new Error('Invalid SESSION_SETUP packet header')
  }

  const req = binary
    .parse(msg.body)
    .word16lu('structureSize')
    .word8('flags')
    .word8('securityMode')
    .word32lu('capabilities')
    .word32lu('channel')
    .word16lu('securityBufferOffset')
    .word16lu('securityBufferLength')
    .word64lu('previousSessionId').vars

  console.log('SESSION_SETUP', req)

  const securityBuffer = msg.buf.slice(req.securityBufferOffset)

  connection.authContext ??= {
    hostName: server.hostName,
    domainName: server.domainName,
  }

  const [status, securityBufferResponse] = AcceptSecurityContext(
    connection.authContext,
    securityBuffer
  )

  if (status === ntstatus.STATUS_SUCCESS) {
    // public static byte[] GenerateSigningKey(byte[] sessionKey, SMB2Dialect dialect, byte[] preauthIntegrityHashValue)
    // {
    //     if (dialect == SMB2Dialect.SMB202 || dialect == SMB2Dialect.SMB210)
    //     {
    //         return sessionKey;
    //     }

    //     if (dialect == SMB2Dialect.SMB311 && preauthIntegrityHashValue == null)
    //     {
    //         throw new ArgumentNullException("preauthIntegrityHashValue");
    //     }

    //     string labelString = (dialect == SMB2Dialect.SMB311) ? "SMBSigningKey" : "SMB2AESCMAC";
    //     byte[] label = GetNullTerminatedAnsiString(labelString);
    //     byte[] context = (dialect == SMB2Dialect.SMB311) ? preauthIntegrityHashValue : GetNullTerminatedAnsiString("SmbSign");

    //     HMACSHA256 hmac = new HMACSHA256(sessionKey);
    //     return SP800_1008.DeriveKey(hmac, label, context, 128);
    // }

    const { sessionKey } = connection.authContext
    connection.signingKey = sessionKey

    // bool signingRequired = (request.SecurityMode & SecurityMode.SigningRequired) > 0;
    // SMB2Dialect smb2Dialect = SMBServer.ToSMB2Dialect(state.Dialect);
    // byte[] signingKey = SMB2Cryptography.GenerateSigningKey(sessionKey, smb2Dialect, null);
  }

  msg.header.sessionId = 12345678 // TODO: bigint...

  const res = put()
    .word16le(9) // StructureSize
    .word16le(0) // SessionFlags
    .word16le(SMB2.HEADER_LENGTH + 8) // SecurityBufferOffset
    .word16le(securityBufferResponse.length) // SecurityBufferLength
    .put(securityBufferResponse) // SecurityBuffer
    .buffer()

  // return result
  return {
    status,
    body: res,
  }
}
