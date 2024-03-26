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
import async from 'async'
import * as utils from '../utils.js'
import ntstatus from '../ntstatus.js'
import * as message from './message.js'
import SMB2 from './constants.js'
import * as cmdHandlers from './cmd/index.js'
import baseLogger from '../logger.js'
const logger = baseLogger.child({ module: 'smb' })

const out = put()
out
  .word16le(0x0009) // StructureSize (fixed according to spec)
  .word8(0) // ErrorContextCount
  .pad(1) // Reserved
  .word32le(0) // ByteCount
  .word8(0) // ErrorData
const SMBERROR_BODY = out.buffer()

/**
 * Handles binary SMB 2.x/3.x messages
 *
 * @param {Buffer} msgBuf - raw message buffer
 * @param {SMBConnection} connection - an SMBConnection instance
 * @param {SMBServer} server - an SMBServer instance
 * @param {Function} cb callback called on completion
 */
function handleRequest(msgBuf, connection, server, cb) {
  let buf = msgBuf
  // dissect compounded requests
  const compMsgs = []
  let msg = message.decode(buf)
  compMsgs.push(msg)
  while (msg.header.nextCommand) {
    buf = buf.slice(msg.header.nextCommand)
    msg = message.decode(buf)
    compMsgs.put(msg)
  }

  if (compMsgs[0].header.relatedOp) {
    sendResponse(compMsgs[0], ntstatus.STATUS_INVALID_PARAMETER, cb)
    return
  }

  const relatedOps = compMsgs.length > 1 && compMsgs[1].header.relatedOp

  // context for related operations
  const relatedCtx = relatedOps
    ? {
        sessionId: compMsgs[0].sessionId,
        treeId: compMsgs[0].treeId,
        fileId: null,
      }
    : null

  function processMsg(msg, callback) {
    const command = SMB2.COMMAND_TO_STRING[msg.header.commandId]
    if (!command) {
      // unknown command
      callback({
        status: ntstatus.STATUS_SMB_BAD_COMMAND,
        message: 'encountered invalid command 0x' + msg.header.commandId.toString(16),
      })
    }
    const handler = cmdHandlers[command]
    if (handler) {
      // process command
      if (msg.header.sessionId) {
        msg.session = connection.sessions[msg.header.sessionId]
        console.assert(msg.session, 'session not found')
      }

      if (msg.header.treeId) {
        msg.tree = connection.trees[msg.header.treeId]
        console.assert(msg.tree, 'tree not found')
      }

      handler(msg, relatedCtx, connection, server).then(
        (result) => {
          if (!result) {
            // special case (see e.g. 'echo' handler): no further processing required
            msg.processed = true
          } else {
            if (result.status !== ntstatus.STATUS_SUCCESS) {
              // command failed
              logger.warn(
                "'" +
                  command.toUpperCase() +
                  "' returned error status " +
                  ntstatus.STATUS_TO_STRING[result.status] +
                  ' (0x' +
                  result.status.toString(16) +
                  ')'
              )
              result.body ??= SMBERROR_BODY
            }
            // stash command result/response
            msg.header.status = result.status
            msg.body = result.body
          }
          callback()
        },
        (err) => {
          // handle this gracefully?
          console.error(err)
          process.exit(1)
        }
      )
    } else {
      // no handler found
      logger.error(
        'encountered unsupported command 0x' +
          msg.header.commandId.toString(16) +
          " '" +
          command.toUpperCase() +
          "'"
      )
      msg.header.status = ntstatus.STATUS_NOT_IMPLEMENTED
      msg.body = SMBERROR_BODY
      callback()
    }
  }

  function processResults(err) {
    sendCompoundedResponses(compMsgs, connection, server, cb)
  }

  // invoke async command handlers
  if (relatedOps) {
    async.eachSeries(compMsgs, processMsg, processResults)
  } else {
    async.each(compMsgs, processMsg, processResults)
  }
}

function sendCompoundedResponses(msgs, connection, server, cb) {
  const out = put()

  if (msgs.length === 1 && msgs[0].processed) {
    // special case (see e.g. 'echo' handler): no further processing required
    cb()
    return
  }

  // build compounded responses
  msgs.forEach(function (msg, n, arr) {
    // make sure the 'reply' flag is set
    msg.header.flags.reply = true
    // if (msg.header.status !== ntstatus.STATUS_SUCCESS) {
    //   msg.body = SMBERROR_BODY;
    // }
    // calculate nextCommand offset
    let nextCommandOff = 0
    let padLength = 0
    if (n < arr.length - 1) {
      nextCommandOff = SMB2.HEADER_LENGTH + msg.body.length
      // align nextCommand on 8-byte boundary
      padLength = utils.calculatePadLength(nextCommandOff, 8)
      nextCommandOff += padLength
    }
    msg.header.nextCommand = nextCommandOff
    out.put(message.encode(msg, connection.signingKey, padLength))
    if (padLength) {
      out.pad(padLength)
    }
  })

  connection.sendRawMessage(out.buffer(), cb)
}

function sendResponse(msg, status, connection, server, cb) {
  // make sure the 'reply' flag is set
  msg.header.flags.reply = true
  msg.header.status = status
  msg.header.nextCommand = 0

  // if (status !== ntstatus.STATUS_SUCCESS) {
  //   msg.body = SMBERROR_BODY;
  // }

  connection.sendRawMessage(message.encode(msg, connection.signingKey), cb)
}

export { handleRequest }
export { sendResponse }
