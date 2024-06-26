/*
 *  Copyright 2016 Adobe Systems Incorporated. All rights reserved.
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

import baseLogger from './logger.js'

import _ from 'lodash'
import * as utils from './utils.js'
const logger = baseLogger.child({ module: 'default' })

const consts = {}

consts.NTLMSSP_SIGNATURE = Buffer.from('NTLMSSP\0', 'ascii')

consts.NTLMSSP_NEGOTIATE_MESSAGE = 1
consts.NTLMSSP_CHALLENGE_MESSAGE = 2
consts.NTLMSSP_AUTHENTICATE_MESSAGE = 3

consts.MESSAGE_TYPE_TO_STRING = {
  1: 'NTLMSSP_NEGOTIATE_MESSAGE',
  2: 'NTLMSSP_CHALLENGE_MESSAGE',
  3: 'NTLMSSP_AUTHENTICATE_MESSAGE',
}

consts.NTLMSSP_NEGOTIATE_MIN_MSG_LENGTH = 16
consts.NTLMSSP_AUTHENTICATE_MIN_MSG_LENGTH = 88

consts.NTLMSSP_REVISION_W2K3 = 0x0f

// NTLMSSP Flags
consts.NTLMSSP_NEGOTIATE_UNICODE = 0x00000001
consts.NTLMSSP_NEGOTIATE_OEM = 0x00000002
consts.NTLMSSP_REQUEST_TARGET = 0x00000004
consts.NTLMSSP_RESERVED_10 = 0x00000008
consts.NTLMSSP_NEGOTIATE_SIGN = 0x00000010
consts.NTLMSSP_NEGOTIATE_SEAL = 0x00000020
consts.NTLMSSP_NEGOTIATE_DATAGRAM = 0x00000040
consts.NTLMSSP_NEGOTIATE_LM_KEY = 0x00000080
consts.NTLMSSP_RESERVED_9 = 0x00000100
consts.NTLMSSP_NEGOTIATE_NTLM = 0x00000200
consts.NTLMSSP_RESERVED_8 = 0x00000400
consts.NTLMSSP_NEGOTIATE_ANONYMOUS = 0x00000800
consts.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000
consts.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000
consts.NTLMSSP_RESERVED_7 = 0x00004000
consts.NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
consts.NTLMSSP_TARGET_TYPE_DOMAIN = 0x00010000
consts.NTLMSSP_TARGET_TYPE_SERVER = 0x00020000
consts.NTLMSSP_RESERVED_6 = 0x00040000
consts.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
consts.NTLMSSP_NEGOTIATE_IDENTIFY = 0x00100000
consts.NTLMSSP_RESERVED_5 = 0x00200000
consts.NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 0x00400000
consts.NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000
consts.NTLMSSP_RESERVED_4 = 0x01000000
consts.NTLMSSP_NEGOTIATE_VERSION = 0x02000000
consts.NTLMSSP_RESERVED_3 = 0x04000000
consts.NTLMSSP_RESERVED_2 = 0x08000000
consts.NTLMSSP_RESERVED_1 = 0x10000000
consts.NTLMSSP_NEGOTIATE_128 = 0x20000000
consts.NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000
consts.NTLMSSP_NEGOTIATE_56 = 0x80000000

// AV Pair Field IDs
consts.NTLMSSP_AV_EOL = 0x0000
consts.NTLMSSP_AV_NB_COMPUTER_NAME = 0x0001
consts.NTLMSSP_AV_NB_DOMAIN_NAME = 0x0002
consts.NTLMSSP_AV_DNS_COMPUTER_NAME = 0x0003
consts.NTLMSSP_AV_DNS_DOMAIN_NAME = 0x0004
consts.NTLMSSP_AV_DNS_TREE_NAME = 0x0005
consts.NTLMSSP_AV_FLAGS = 0x0006
consts.NTLMSSP_AV_TIMESTAMP = 0x0007
consts.NTLMSSP_AV_RESTRICTION = 0x0008
consts.NTLMSSP_AV_TARGET_NAME = 0x0009
consts.NTLMSSP_AV_CHANNEL_BINDINGS = 0x000a

function parseMessageType(buf) {
  if (buf.length < consts.NTLMSSP_SIGNATURE.length + 4) {
    logger.warn(
      'invalid NTLMSSP message: expected length: >=%d, actual length: %d, data: 0x%s',
      consts.NTLMSSP_SIGNATURE.length + 4,
      buf.length,
      buf.toString('hex')
    )
    return -1
  }

  let off = 0
  const sig = buf.slice(off, consts.NTLMSSP_SIGNATURE.length)
  off += consts.NTLMSSP_SIGNATURE.length
  if (!utils.bufferEquals(consts.NTLMSSP_SIGNATURE, sig)) {
    logger.warn('invalid NTLMSSP message signature: data: 0x%s', sig.toString('hex'))
    return -1
  }

  // type
  return buf.readUInt32LE(off)
}

function parseNegotiateMessage(buf) {
  const type = parseMessageType(buf)
  if (type !== consts.NTLMSSP_NEGOTIATE_MESSAGE) {
    logger.warn(
      'invalid NTLMSSP message type: expected: %s, actual: %s',
      consts.MESSAGE_TYPE_TO_STRING[consts.NTLMSSP_NEGOTIATE_MESSAGE],
      consts.MESSAGE_TYPE_TO_STRING[type]
    )
    return null
  }

  if (buf.length < consts.NTLMSSP_NEGOTIATE_MIN_MSG_LENGTH) {
    logger.warn(
      'invalid NTLMSSP_NEGOTIATE message: expected length: >=%d, actual length: %d, data: 0x%s',
      consts.NTLMSSP_NEGOTIATE_MIN_MSG_LENGTH,
      buf.length,
      buf.toString('hex')
    )
    return null
  }

  let off = consts.NTLMSSP_SIGNATURE.length + 4
  const flags = buf.readUInt32LE(off)
  off += 4

  const msg = {
    type,
    flags,
  }

  // minimal message size (16 bytes) includes just signature, type and flags
  if (buf.length === consts.NTLMSSP_NEGOTIATE_MIN_MSG_LENGTH) {
    return msg
  }

  if (buf.length < consts.NTLMSSP_NEGOTIATE_MIN_MSG_LENGTH + 8 + 8) {
    logger.warn(
      'invalid NTLMSSP_NEGOTIATE message: expected length: >=%d, actual length: %d, data: 0x%s',
      consts.NTLMSSP_NEGOTIATE_MIN_MSG_LENGTH + 8 + 8,
      buf.length,
      buf.toString('hex')
    )
    return null
  }

  const domainLength = buf.readUInt16LE(off)
  off += 2
  const domainMaxLength = buf.readUInt16LE(off)
  off += 2
  const domainOffset = buf.readUInt32LE(off)
  off += 4
  const workstationLength = buf.readUInt16LE(off)
  off += 2
  const workstationMaxLength = buf.readUInt16LE(off)
  off += 2
  const workstationOffset = buf.readUInt32LE(off)
  off += 4

  // OS Version structure is optional
  if (
    off != domainOffset &&
    off != workstationOffset &&
    buf.length >= consts.NTLMSSP_NEGOTIATE_MIN_MSG_LENGTH + 8 + 8 + 8
  ) {
    const productMajorVersion = buf.readUInt8(off)
    off += 1
    const productMinorVersion = buf.readUInt8(off)
    off += 1
    const productBuild = buf.readUInt16LE(off)
    off += 2
    off += 3 // reserved
    const ntlmRevisionCurrent = buf.readUInt8(off)
    off += 1
  }

  if (flags & consts.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED && domainOffset) {
    if (domainOffset + domainLength > buf.length) {
      logger.warn(
        'invalid NTLMSSP message: domainOffset: %d, domainLength: %d, msgLength: %s',
        domainOffset,
        domainLength,
        buf.length
      )
      return null
    }
    msg.domain = buf.slice(domainOffset, domainOffset + domainLength).toString('ascii')
  }

  if (flags & consts.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED && workstationOffset) {
    if (workstationOffset + workstationLength > buf.length) {
      logger.warn(
        'invalid NTLMSSP message: workstationOffset: %d, workstationLength: %d, msgLength: %s',
        workstationOffset,
        workstationLength,
        buf.length
      )
      return null
    }
    msg.workstation = buf
      .slice(workstationOffset, workstationOffset + workstationLength)
      .toString('ascii')
  }

  return msg
}

function createChallengeMessage(negotiateFlags, challenge, targetName, domainName) {
  const computerName = targetName.split('.')[0].toUpperCase()
  const dnsDomain = targetName.split('.').slice(1).join('.')

  const targetNameLen = negotiateFlags & consts.NTLMSSP_REQUEST_TARGET ? computerName.length * 2 : 0
  const targetNameOffset = 56

  const smbTime = utils.systemToSMBTime(Date.now())
  const info = put()
  info
    .word16le(consts.NTLMSSP_AV_NB_COMPUTER_NAME)
    .word16le(computerName.length * 2)
    .put(Buffer.from(computerName.toUpperCase(), 'utf16le'))
    .word16le(consts.NTLMSSP_AV_NB_DOMAIN_NAME)
    .word16le(domainName.length * 2)
    .put(Buffer.from(domainName.toUpperCase(), 'utf16le'))
    .word16le(consts.NTLMSSP_AV_DNS_COMPUTER_NAME)
    .word16le(targetName.length * 2)
    .put(Buffer.from(targetName, 'utf16le'))
    .word16le(consts.NTLMSSP_AV_DNS_DOMAIN_NAME)
    .word16le(dnsDomain.length * 2)
    .put(Buffer.from(dnsDomain, 'utf16le'))
    .word16le(consts.NTLMSSP_AV_TIMESTAMP)
    .word16le(8)
    .word32le(smbTime.getLowBits())
    .word32le(smbTime.getHighBits())
    .word16le(consts.NTLMSSP_AV_EOL) // MsvAvEOL
    .word16le(0)

  // force target info (windows clients seem to require it)
  negotiateFlags |= consts.NTLMSSP_NEGOTIATE_TARGET_INFO

  const targetInfoLen = negotiateFlags & consts.NTLMSSP_NEGOTIATE_TARGET_INFO ? info.length() : 0
  const targetInfoOffset = targetNameOffset + targetNameLen

  const supportedFlags =
    consts.NTLMSSP_NEGOTIATE_128 |
    consts.NTLMSSP_NEGOTIATE_VERSION |
    consts.NTLMSSP_NEGOTIATE_NTLM |
    consts.NTLMSSP_REQUEST_TARGET |
    consts.NTLMSSP_NEGOTIATE_TARGET_INFO |
    consts.NTLMSSP_NEGOTIATE_UNICODE
  let flags = negotiateFlags & supportedFlags
  flags |= consts.NTLMSSP_TARGET_TYPE_SERVER

  const out = put()
  out
    .put(consts.NTLMSSP_SIGNATURE) // Signature
    .word32le(consts.NTLMSSP_CHALLENGE_MESSAGE) // MessageType
    .word16le(targetNameLen) // TargetNameLen
    .word16le(targetNameLen) // TargetNameMaxLen
    .word32le(targetNameOffset) // TargetNameBufferOffset
    .word32le(negotiateFlags) // NegotiateFlags
    .put(challenge) // ServerChallenge
    .pad(8) // Reserved
    .word16le(targetInfoLen) // TargetInfoLen
    .word16le(targetInfoLen) // TargetInfoMaxLen
    .word32le(targetInfoOffset) // TargetInfoBufferOffset
    .word8(0x06) // ProductMajorVersion
    .word8(0x01) // ProductMajorVersion
    .word16le(7600) // ProductBuild
    .pad(3) // Reserved
    .word8(consts.NTLMSSP_REVISION_W2K3) // NTLMRevisionCurrent
    .put(Buffer.from(computerName, 'utf16le')) // TargetName
    .put(info.buffer()) // TargetInfo

  return out.buffer()
}

function parseAuthenticateMessage(buf) {
  const type = parseMessageType(buf)
  if (type !== consts.NTLMSSP_AUTHENTICATE_MESSAGE) {
    logger.warn(
      'invalid NTLMSSP message type: expected: %s, actual: %s',
      consts.MESSAGE_TYPE_TO_STRING[consts.NTLMSSP_AUTHENTICATE_MESSAGE],
      consts.MESSAGE_TYPE_TO_STRING[type]
    )
    return null
  }

  if (buf.length < consts.NTLMSSP_AUTHENTICATE_MIN_MSG_LENGTH) {
    logger.warn(
      'invalid NTLMSSP_AUTHENTICATE message: expected length: >=%d, actual length: %d, data: 0x%s',
      consts.NTLMSSP_AUTHENTICATE_MIN_MSG_LENGTH,
      buf.length,
      buf.toString('hex')
    )
    return null
  }

  let off = consts.NTLMSSP_SIGNATURE.length + 4
  const lmResponseLength = buf.readUInt16LE(off)
  off += 2
  const lmResponseMaxLength = buf.readUInt16LE(off)
  off += 2
  const lmResponseOffset = buf.readUInt32LE(off)
  off += 4
  const ntResponseLength = buf.readUInt16LE(off)
  off += 2
  const ntResponseMaxLength = buf.readUInt16LE(off)
  off += 2
  const ntResponseOffset = buf.readUInt32LE(off)
  off += 4
  const domainLength = buf.readUInt16LE(off)
  off += 2
  const domainMaxLength = buf.readUInt16LE(off)
  off += 2
  const domainOffset = buf.readUInt32LE(off)
  off += 4
  const userLength = buf.readUInt16LE(off)
  off += 2
  const userMaxLength = buf.readUInt16LE(off)
  off += 2
  const userOffset = buf.readUInt32LE(off)
  off += 4
  const workstationLength = buf.readUInt16LE(off)
  off += 2
  const workstationMaxLength = buf.readUInt16LE(off)
  off += 2
  const workstationOffset = buf.readUInt32LE(off)
  off += 4
  const sessionKeyLength = buf.readUInt16LE(off)
  off += 2
  const sessionKeyMaxLength = buf.readUInt16LE(off)
  off += 2
  const sessionKeyOffset = buf.readUInt32LE(off)
  off += 4
  const flags = buf.readUInt32LE(off)
  off += 4
  const productMajorVersion = buf.readUInt8(off)
  off += 1
  const productMinorVersion = buf.readUInt8(off)
  off += 1
  const productBuild = buf.readUInt16LE(off)
  off += 2
  off += 3 // reserved
  const ntlmRevisionCurrent = buf.readUInt8(off)
  off += 1
  const mic = buf.slice(off, off + 16)
  off += 16

  const msg = {
    type,
    flags,
    mic,
  }

  msg.lmResponse = buf.slice(lmResponseOffset, lmResponseOffset + lmResponseLength)
  msg.ntResponse = buf.slice(ntResponseOffset, ntResponseOffset + ntResponseLength)
  msg.user = buf.slice(userOffset, userOffset + userLength).toString('utf16le')
  msg.domain = buf.slice(domainOffset, domainOffset + domainLength).toString('utf16le')
  msg.workstation = buf
    .slice(workstationOffset, workstationOffset + workstationLength)
    .toString('utf16le')
  msg.sessionKey = buf.slice(sessionKeyOffset, sessionKeyOffset + sessionKeyLength)

  return msg
}

export default consts

export { parseMessageType }
export { parseNegotiateMessage }
export { createChallengeMessage }
export { parseAuthenticateMessage }
