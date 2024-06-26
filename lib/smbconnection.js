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

import baseLogger from './logger.js'

import async from 'async'
import SMB from './smb/constants.js'
import SMB2 from './smb2/constants.js'
import * as utils from './utils.js'
import * as smb from './smb/handler.js'
import * as smb2 from './smb2/handler.js'
const logger = baseLogger.child({ module: 'smb' })

/**
 * Creates an <code>SMBConnection</code> instance. This objects takes care of reading and writing
 * SMB messages on the wire and delegating the message processing to specialised handlers.
 *
 * @param {Socket} socket - tcp socket
 * @param {Object} server - smb server
 * @constructor
 */
class SMBConnection {
  constructor(socket, server) {
    this.socket = socket
    this.server = server

    this.socket.on('data', this.onData.bind(this))
    this.socket.on('close', this.onClose.bind(this))
  }

  onData(data) {
    logger.trace('received %d bytes: %s', data.length, data.toString('hex'))

    if (this.partialMsgChunk) {
      // prepend leftover chunk from previous event
      data = Buffer.concat([this.partialMsgChunk, data])
      delete this.partialMsgChunk
    }

    let buf = data

    const msgChunks = []
    while (buf.length > 4) {
      // parse NetBIOS session service header (RFC 1002)
      const nbType = buf.readUInt8(0)
      // since we're assuming native SMB (i.e. over TCP)
      // we're only supporting NetBIOS session messages
      if (nbType !== 0x00) {
        logger.error('unsupported NetBIOS session service message type: %d', nbType)
        this.socket.destroy()
        return
      }

      // native SMB message headers consist of 8-bit type and 24-bit length;
      // since type is 0 we can read the length as 32-bit unsigned int.
      // (NetBIOS uses big-endian (network) byte order)
      const smbLen = buf.readUInt32BE(0)
      if (smbLen > buf.length - 4) {
        // partial msg chunk, wait for next chunk
        break
      }

      // strip NetBIOS session service header
      buf = buf.slice(4)

      msgChunks.push(buf.slice(0, smbLen))

      buf = buf.slice(smbLen)
    }
    // by now we should have consumed all msg chunks
    if (buf.length) {
      // store leftover partial msg chunk and prepend on next data event
      this.partialMsgChunk = buf
    }

    if (!msgChunks.length) {
      return
    }

    const self = this
    async.each(
      msgChunks,
      function (chunk, callback) {
        // sniff SMB version
        const protocolId = chunk.slice(0, 4)
        if (utils.bufferEquals(protocolId, SMB.PROTOCOL_ID)) {
          // CIFS/SMB 1.0
          smb.handleRequest(chunk, self, self.server, callback)
        } else if (utils.bufferEquals(protocolId, SMB2.PROTOCOL_ID)) {
          // SMB 2.x/3.x
          smb2.handleRequest(chunk, self, self.server, callback)
        } else {
          // ???
          callback(
            'invalid SMB protocol id: ' +
              protocolId.toString('hex') +
              ', data: ' +
              chunk.toString('hex')
          )
        }
      },
      function (err) {
        if (err) {
          logger.error('encountered error during message processing', err)
        }
      }
    )
  }

  onClose(hadErrors) {
    // todo cleanup connection state
  }

  sendRawMessage(msgBuf, cb) {
    const hdrBuf = Buffer.alloc(4)
    // native SMB message headers consist of 8-bit type and 24-bit length;
    // since NetBIOS session message type is 0 we can write the length as 32-bit unsigned int.
    // (NetBIOS uses big-endian (network) byte order)
    hdrBuf.writeUInt32BE(msgBuf.length, 0)
    this.socket.write(Buffer.concat([hdrBuf, msgBuf]), cb)
  }
}

export default SMBConnection
