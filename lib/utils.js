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

import crypto from 'node:crypto'

import Path from 'node:path'
import Long from 'long'
import mime from 'mime'
import unorm from 'unorm'

// register (unofficial) mime type for InDesign files (.indd)
mime.define({ 'application/x-indesign': ['indd'] })

/**
 * Lookup a mime type based on file extension.
 *
 * @param {String} path resource path
 * @param {String} [fallback] fallback mime type if none is found
 * @return {String} mime type associated with the specified file type
 */
export function lookupMimeType(path, fallback) {
  return mime.lookup(path, fallback)
}

/**
 * Number of milliseconds between Jan 1, 1601, 00:00:00 UTC and Jan 1, 1970, 00:00:00.0.
 */
const DELTA_EPOCH_MS = 11644473600000

/**
 * indicates that extended attribute (EA) support is required on this file
 */
const FILE_NEED_EA = 0x80

/**
 * Converts the system time (number of milliseconds since Jan 1, 1970, 00:00:00 UTC)
 * to the SMB format time (number of 100ns since Jan 1, 1601, 00:00:00 UTC).
 *
 * @param {Number} ms number of milliseconds since Jan 1, 1970, 00:00:00 UTC.
 * @return {Long} a 64bit signed integer representing the number of 100ns since Jan 1, 1601, 00:00:00 UTC.
 */
export function systemToSMBTime(ms) {
  const l = Long.fromNumber(ms)
  return l.add(DELTA_EPOCH_MS).multiply(10000)
}

/**
 * Converts the SMB format time (number of 100ns since Jan 1, 1601, 00:00:00 UTC)
 * to the number of milliseconds since Jan 1, 1970, 00:00:00 UTC.
 *
 * @param {Long} l a 64bit signed integer representing the number of 100ns since Jan 1, 1601, 00:00:00 UTC.
 * @return {Number} number of milliseconds since Jan 1, 1970, 00:00:00 UTC.
 */
export function smbToSystemTime(l) {
  return l.div(10000).subtract(DELTA_EPOCH_MS).toNumber()
}

/**
 * Converts the system time (number of milliseconds since Jan 1, 1970, 00:00:00 UTC)
 * to the legacy 16bit SMB_DATE representation.
 *
 * @param {Number} ms number of milliseconds since Jan 1, 1970, 00:00:00 UTC.
 * @return {Number} a 16bit integer SMB_DATE value.
 */
export function systemToLegacySMBDate(ms) {
  const date = new Date(ms)
  let result = date.getDate()
  result += (date.getMonth() + 1) << 5
  result += (date.getFullYear() - 1980) << 9
  return result
}

/**
 * Converts the system time (number of milliseconds since Jan 1, 1970, 00:00:00 UTC)
 * to the legacy 16bit SMB_TIME representation.
 *
 * @param {Number} ms number of milliseconds since Jan 1, 1970, 00:00:00 UTC.
 * @return {Number} a 16bit integer SMB_TIME value.
 */
export function systemToLegacySMBTime(ms) {
  const date = new Date(ms)
  let result = Math.floor(date.getSeconds() / 2)
  result += date.getMinutes() << 5
  result += date.getHours() << 11
  return result
}

/**
 * Converts the legacy 16bit SMB_DATE and SMB_TIME representation to system time (number of milliseconds since Jan 1, 1970, 00:00:00 UTC).
 *
 * @param {Number} smbDate 16bit integer SMB_DATE
 * @param {Number} smbTime 16bit integer SMB_TIME
 * @return {Number} number of milliseconds since Jan 1, 1970, 00:00:00 UTC.
 */
export function legacySMBToSystemDateTime(smbDate, smbTime) {
  const year = ((smbDate & 0xfe00) >> 9) + 1980
  const month = ((smbDate & 0x01e0) >> 5) - 1
  const day = smbDate & 0x001f
  const hour = (smbTime & 0xf800) >> 11
  const minutes = (smbTime & 0x07e0) >> 5
  const seconds = (smbTime & 0x001f) * 2
  return new Date(year, month, day, hour, minutes, seconds).getTime()
}

/**
 * Reads the 8 byte SMB format time and returns the
 * milliseconds since 1 January 1970 00:00:00 UTC (Unix Epoch).
 *
 * The following rules apply:
 * If the read 64bit value is -1 (0xFFFFFFFFFFFFFFFF) the return value is -1;
 * If the read 64bit value is 0 (0x0000000000000000) the return value is 0;
 * All other values are converted to the Unix Epoch.
 *
 * @param {Buffer} buf
 * @param {Number} pos
 * @return {Number} milliseconds since 1 January 1970 00:00:00 UTC (Unix Epoch)
 */
export function readTimestamp(buf, pos) {
  const timeLow = buf.readUInt32LE(pos)
  const timeHigh = buf.readUInt32LE(pos + 4)
  if (timeLow === 0xffffffff && timeHigh === 0xffffffff) {
    return -1
  } else if (!timeHigh && !timeLow) {
    return 0
  } else {
    return new Date(smbToSystemTime(new Long(timeLow, timeHigh))).getTime()
  }
}

/**
 * Parses an encoded FEA (full extended attribute) list.
 *
 * @param {Buffer} buf
 * @param {Number} pos
 * @return {Object[]} array of objects representing the extended attributes
 */
export function parseFEAList(buf, pos) {
  if (buf.length - pos < 4) {
    return null
  }
  const result = []
  const sizeOfListInBytes = buf.readUInt32LE(pos)
  if (sizeOfListInBytes <= 4) {
    return result
  }
  pos += 4
  buf = buf.slice(pos, pos + sizeOfListInBytes - 4)
  pos = 0
  let flag, nameLength, valueLenght
  while (pos < buf.length - 5) {
    const ea = {}
    ea.offset = pos
    flag = buf.readUInt8(pos)
    pos += 1
    nameLength = buf.readUInt8(pos)
    pos += 1
    valueLenght = buf.readUInt32LE(pos)
    pos += 2
    // zero-terminated ascii string
    ea.name = buf.slice(pos, pos + nameLength).toString('ascii')
    pos += nameLength + 1
    // non-zero-terminated ascii string
    ea.value = buf.slice(pos, pos + valueLenght).toString('ascii')
    pos += valueLenght
    ea.needEA = !!(flag & FILE_NEED_EA)
    result.push(ea)
  }
  return result
}

/**
 * Extracts the bytes of an 0x0000-delimited utf16le encoded string (excluding the delimiter)
 * @param buf
 * @param pos
 * @return {Buffer} bytes of a utf16le encoded string (excluding the 0x0000 delimiter)
 */
export function extractUnicodeBytes(buf, pos) {
  let off = pos
  while (buf.readUInt16LE(off)) {
    off += 2
  }

  return buf.slice(pos, off)
}

/**
 * Extracts the bytes of an 0x00-delimited ascii encoded string (excluding the delimiter)
 * @param buf
 * @param pos
 * @return {Buffer} bytes of an ascii encoded string (excluding the 0x00 delimiter)
 */
export function extractAsciiBytes(buf, pos) {
  let off = pos
  while (buf.readUInt8(off)) {
    off += 1
  }

  return buf.slice(pos, off)
}

export function calculatePadLength(offset, alignment) {
  const pad = alignment - (offset % alignment)
  return pad < alignment ? pad : 0
}

/**
 * Normalize a SMB file path or pattern. Converts backslashes to slashes, makes sure
 * the path name is absolute, and removes a trailing slash.
 *
 * @param {String} name name to normalize
 * @returns {String} normalized name
 */
export function normalizeSMBFileName(name) {
  name = name.replace(/\\/g, '/')
  if (!name.length || (name.length && name.charAt(0) !== '/')) {
    name = '/' + name
  }
  if (name.length > 1 && name.substr(-1) === '/') {
    name = name.substr(0, name.length - 1)
  }
  return name
}

export function bufferEquals(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    return undefined
  }
  if (typeof a.equals === 'function') {
    // node >= v0.12
    return a.equals(b)
  }

  if (a.length !== b.length) {
    return false
  }

  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false
    }
  }

  return true
}

/**
 * Returns the last segment of a path
 *
 * @param {String} path
 * @return {String} last segment of path
 */
export function getPathName(path) {
  const pos = path.lastIndexOf(Path.sep)
  if (pos === -1) {
    return path
  }
  return path.slice(pos + 1)
}

/**
 * Returns the file extension
 *
 * @param {String} name path or file name
 * @returns {String} file extension
 */
export function getFileExtension(name) {
  const pos = name.lastIndexOf('.')
  if (pos === -1) {
    return name
  }
  return name.slice(pos + 1)
}

/**
 * Returns the parent path
 *
 * @param {String} path
 * @return {String} parent path
 */
export function getParentPath(path) {
  const pos = path.lastIndexOf(Path.sep)
  if (pos === -1) {
    return null
  }
  if (pos === 0) {
    return Path.sep
  }
  return path.slice(0, pos)
}

/**
 * Strips the specified parent path
 *
 * @param {String} path
 * @param {String} parentPath
 * @return {String} stripped path
 */
export function stripParentPath(path, parentPath) {
  if (path === parentPath) {
    return ''
  }
  if (path.indexOf(parentPath) === 0) {
    path = path.substr(parentPath.length)
    if (path.length > 1 && path.substr(-1) === Path.sep) {
      // strip trailing slash
      path = path.substr(0, path.length - 1)
    }
  }
  return path
}

export function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min
}

export function generateRawUUID() {
  let timeLow, timeMid, timeHiAndVersion, clockSeqHiAndReserved, clockSeqLow, node

  timeLow = getRandomInt(0, Math.pow(2, 32) - 1)
  timeMid = getRandomInt(0, Math.pow(2, 16) - 1)
  timeHiAndVersion = 0x4000 | getRandomInt(0, Math.pow(2, 12) - 1)
  clockSeqHiAndReserved = 0x80 | getRandomInt(0, Math.pow(2, 6) - 1)
  clockSeqLow = getRandomInt(0, Math.pow(2, 8) - 1)
  node = crypto.randomBytes(6)

  const buf = Buffer.alloc(16)
  let off = 0
  buf.writeUInt32LE(timeLow, off)
  off += 4
  buf.writeUInt16LE(timeMid, off)
  off += 2
  buf.writeUInt16LE(timeHiAndVersion, off)
  off += 2
  buf.writeUInt8(clockSeqHiAndReserved, off)
  off += 1
  buf.writeUInt8(clockSeqLow, off)
  off += 1
  node.copy(buf, off)

  return buf
}

export function rawUUIDToString(buf) {
  const uuid = parseRawUUID(buf)
  return (
    decimalToHex(uuid.timeLow, 8) +
    '-' +
    decimalToHex(uuid.timeMid, 4) +
    '-' +
    decimalToHex(uuid.timeHiAndVersion, 4) +
    '-' +
    decimalToHex(uuid.clockSeqHiAndReserved, 2) +
    decimalToHex(uuid.clockSeqLow, 2) +
    '-' +
    uuid.node.toString('hex')
  )
}

export function parseRawUUID(buf) {
  const uuid = {}
  let off = 0
  uuid.timeLow = buf.readUInt32LE(off)
  off += 4
  uuid.timeMid = buf.readUInt16LE(off)
  off += 2
  uuid.timeHiAndVersion = buf.readUInt16LE(off)
  off += 2
  uuid.clockSeqHiAndReserved = buf.readUInt8(off)
  off += 1
  uuid.clockSeqLow = buf.readUInt8(off)
  off += 1
  uuid.node = buf.slice(off, off + 6)
  return uuid
}

export function rawUUIDFromString(str) {
  // todo validation / error handling
  const parts = str.split('-')
  // parts.length === 5
  const b1 = Buffer.from(parts[0], 'hex')
  const b2 = Buffer.from(parts[1], 'hex')
  const b3 = Buffer.from(parts[2], 'hex')
  const b4 = Buffer.from(parts[3].substr(0, 2), 'hex')
  const b5 = Buffer.from(parts[3].substr(2), 'hex')
  const b6 = Buffer.from(parts[4], 'hex')
  return Buffer.concat([b1, b2, b3, b4, b5, b6])
}

export function decimalToHex(d, padding) {
  let hex = Number(d).toString(16)
  padding = typeof padding === 'undefined' || padding === null ? 2 : padding
  while (hex.length < padding) {
    hex = '0' + hex
  }
  return hex
}

export function unicodeNormalize(str) {
  // need to normalize unicode strings in order to avoid issues related to different code points (e.g. 'caf\u00E9' vs 'cafe\u0301').
  // note that using the builtin string.normalize('NFKD') does not work...
  return unorm.nfkd(str)
}

export function unicodeEquals(str1, str2) {
  return unicodeNormalize(str1) === unicodeNormalize(str2)
}

export const EMPTY_BUFFER = Buffer.alloc(0)
export const ZERO_GUID = Buffer.alloc(16, 0)
