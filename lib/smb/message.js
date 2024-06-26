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
import ntstatus from '../ntstatus.js'
import consts from './constants.js'
import * as flags from './flags.js'

function decode(buf) {
  // SMB uses little endian byte order!
  const parser = binary.parse(buf)
  const raw = parser
    .buffer('protocolId', 4) // 0xff, 'S', 'M', 'B'
    .word8('command')
    .word32le('status')
    .word8('flags')
    .word16le('flags2')
    .word16le('extra.pidHigh')
    .buffer('extra.signature', 8)
    .skip(2)
    .word16le('tid')
    .word16le('pidLow')
    .word16le('uid')
    .word16le('mid')
    .word8('params.wordCount')
    .buffer('params.words', 2 * parser.vars.params.wordCount)
    .word16le('data.byteCount')
    .buffer('data.bytes', 'data.byteCount').vars

  const cmdId = raw.command
  const header = {
    commandId: cmdId,
    command: consts.COMMAND_TO_STRING[cmdId],
    status: raw.status,
    flags: flags.decode(raw.flags, raw.flags2),
    extra: {
      pidHigh: raw.extra.pidHigh,
      signature: raw.extra.signature,
    },
    tid: raw.tid,
    pidLow: raw.pidLow,
    pid: (raw.extra.pidHigh << 16) + raw.pidLow,
    uid: raw.uid,
    mid: raw.mid,
  }

  const params = raw.params.words
  const paramsOffset = consts.SMB_MIN_LENGTH
  const data = raw.data.bytes
  const dataOffset = paramsOffset + params.length

  const msg = {
    protocolId: raw.protocolId,
    header,
    params,
    data,
    buf, // raw message buffer
  }

  // unify andX and non-andX style message format: commands will be represented as array, even for andX-style messages
  msg.commands = []
  decodeCommands(buf, header.commandId, params, data, paramsOffset, dataOffset, msg.commands)

  return msg
}

function decodeCommands(buf, commandId, params, data, paramsOffset, dataOffset, commands) {
  commands.push({
    commandId,
    params,
    data,
    paramsOffset,
    dataOffset,
  })

  if (!consts.IS_ANDX_COMMAND(commandId)) {
    return
  }

  // parse andX prefix
  const nextCmdId = params.readUInt8(0)
  const offset = params.readUInt16LE(2)

  let nextParamsOffset, nextDataOffset
  if (nextCmdId !== 0xff && offset) {
    // extract params & data
    const nextBody = buf.slice(offset)
    let off = 0
    const wordCount = nextBody.readUInt8(off)
    nextParamsOffset = off += 1
    const nextParams = nextBody.slice(off, off + 2 * wordCount)
    off += 2 * wordCount
    const byteCount = nextBody.readUInt16LE(off)
    nextDataOffset = off += 2
    const nextData = nextBody.slice(off, off + byteCount)

    // recurse
    decodeCommands(buf, nextCmdId, nextParams, nextData, nextParamsOffset, nextDataOffset, commands)
  }
}

function encode(msg) {
  const out = put()

  const flgs = flags.encode(msg.header.flags)

  // header
  out
    .put(msg.protocolId)
    .word8(msg.header.commandId)
    .word32le(msg.header.status)
    .word8(flgs.flags)
    .word16le(flgs.flags2)
    .word16le(msg.header.extra.pidHigh)
    .put(msg.header.extra.signature)
    .pad(2)
    .word16le(msg.header.tid)
    .word16le(msg.header.pid)
    .word16le(msg.header.uid)
    .word16le(msg.header.mid)

  let offset = consts.SMB_HEADER_LENGTH

  let wordCount, byteCount

  // body (params, data)
  if (
    msg.header.status !== ntstatus.STATUS_SUCCESS &&
    msg.header.status !== ntstatus.STATUS_MORE_PROCESSING_REQUIRED
  ) {
    // error message
    // according to the CIFS spec:
    // "Error responses SHOULD be sent with empty SMB Parameters and SMB Data blocks"
    out
      .word8(0) // wordCount
      .word16le(0) // byteCount
  } else if (!consts.IS_ANDX_COMMAND(msg.header.commandId)) {
    // regular message body with single params/data pair
    msg.params = msg.commands[0].params
    wordCount = msg.params.length / 2
    if (msg.commands[0].wordCount) {
      // override wordCount
      wordCount = msg.commands[0].wordCount
    }
    msg.data = msg.commands[0].data
    byteCount = msg.data.length
    if (msg.commands[0].byteCount) {
      // override byteCount
      byteCount = msg.commands[0].byteCount
    }
    // wordCount
    out
      .word8(wordCount)
      // params
      .put(msg.params)
      // byteCount
      .word16le(byteCount)
      // data
      .put(msg.data)
  } else {
    // andX-type message body with multiple params/data pairs
    for (let i = 0; i < msg.commands.length; i++) {
      const cmd = msg.commands[i]
      // next params/data block offset
      offset += 1 + cmd.params.length + 2 + cmd.data.length

      wordCount = cmd.params.length / 2
      if (cmd.wordCount) {
        // override wordCount
        wordCount = cmd.wordCount
      }

      byteCount = cmd.data.length
      if (cmd.byteCount) {
        // override byteCount
        byteCount = cmd.byteCount
      }

      // wordCount
      out.word8(wordCount)
      // andX header
      if (i === msg.commands.length - 1) {
        // last command in chain
        if (consts.IS_ANDX_COMMAND(cmd.commandId)) {
          // next andX command
          cmd.params.writeUInt8(0xff, 0)
          // andX reserved
          cmd.params.writeUInt8(0x0, 1)
          // andX offset
          cmd.params.writeUInt16LE(0x0, 2)
        }
      } else {
        // next andX command
        cmd.params.writeUInt8(msg.commands[i + 1].commandId, 0)
        // andX reserved
        cmd.params.writeUInt8(0x0, 1)
        // andX offset
        cmd.params.writeUInt16LE(offset, 2)
      }
      // params
      out
        .put(cmd.params)
        // byteCount
        .word16le(byteCount)
        // data
        .put(cmd.data)
    }
  }

  return out.buffer()
}

export { decode }
export { encode }
