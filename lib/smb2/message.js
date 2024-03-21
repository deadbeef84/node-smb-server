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
const Long = require('long')
const crypto = require('node:crypto')
const aesCmac = require('node-aes-cmac').aesCmac

const ntstatus = require('../ntstatus')
const consts = require('./constants')
const flags = require('./flags')

function decode(buf) {
  // SMB uses little endian byte order!
  const parser = binary.parse(buf)
  // header
  const raw = parser
    .buffer('protocolId', 4) // 0xfe, 'S', 'M', 'B'
    .word16le('structureSize') // 64
    .word16le('creditCharge')
    .word32le('status')
    .word16le('command')
    .word16le('creditReqRes')
    .word32le('flags')
    .word32le('nextCommand')
    .word64le('messageId')
    .skip(4) // reserved
    .word32le('treeId')
    .word64le('sessionId')
    .buffer('signature', 16).vars

  // raw body
  const body = buf.slice(consts.HEADER_LENGTH, raw.nextCommand ? raw.nextCommand : buf.length)

  const cmdId = raw.command
  const header = {
    commandId: cmdId,
    command: consts.COMMAND_TO_STRING[cmdId],
    status: raw.status,
    creditCharge: raw.creditCharge,
    creditReqRes: raw.creditReqRes,
    flags: flags.decode(raw.flags),
    nextCommand: raw.nextCommand,
    messageId: raw.messageId,
    treeId: raw.treeId,
    sessionId: raw.sessionId,
    signature: raw.signature,
  }

  return {
    protocolId: raw.protocolId,
    header,
    body, // raw message body
    buf, // raw message buffer
  }
}

function encode(msg, key, pad) {
  const out = put()

  msg.header.flags.signed = Boolean(key)
  msg.header.flags.reply = true
  const flgs = flags.encode(msg.header.flags)

  // header
  out
    .put(msg.protocolId)
    .word16le(consts.HEADER_LENGTH)
    .word16le(msg.header.creditCharge)
    .word32le(msg.header.status)
    .word16le(msg.header.commandId)
    .word16le(msg.header.creditReqRes)
    .word32le(flgs)
    .word32le(msg.header.nextCommand)
    .word64le(msg.header.messageId)
    .pad(4)
    .word32le(msg.header.treeId)
    .word64le(msg.header.sessionId)
    .pad(16) // signature
    // body
    .put(msg.body)

  const buf = out.buffer()

  if (key) {
    // SMB2
    const signature = crypto
      .createHmac('sha256', key)
      .update(buf)
      .update(Buffer.alloc(pad || 0, 0))
      .digest()

    // SMB3
    // let signature = aesCmac(key, buf, { returnAsBuffer: true })

    signature.copy(buf, consts.HEADER_LENGTH - 16, 0, 16)

    // console.log('ENCODE', {
    //   command: msg.header.commandId,
    //   key,
    //   pad,
    //   signature: signature.subarray(0, 16),
    //   signatureFull: signature,
    // })
  }

  return buf
}

module.exports.decode = decode
module.exports.encode = encode
