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

const path = require('path')
const fs = require('fs')
const put = require('put')
const binary = require('binary')
const logger = require('winston').loggers.get('smb')
const _ = require('lodash')

const ntstatus = require('../../ntstatus')
const SMB = require('../constants')
const utils = require('../../utils')

const subCmdHandlers = {}

function loadSubCmdHandlers() {
  const p = path.join(__dirname, 'trans2')
  const files = fs.readdirSync(p)
  for (let i = 0; i < files.length; i++) {
    let f = files[i]
    const stat = fs.statSync(path.resolve(p, f))
    if (stat.isDirectory()) {
      continue
    }
    if (f.substr(-3) === '.js') {
      f = f.slice(0, -3)
      subCmdHandlers[f] = require(path.resolve(p, f))
    }
  }
}
loadSubCmdHandlers()

/**
 * SMB_COM_TRANSACTION2 (0x32): Transaction 2 format request/response.
 *
 * @param {Object} msg - an SMB message object
 * @param {Number} commandId - the command id
 * @param {Buffer} commandParams - the command parameters
 * @param {Buffer} commandData - the command data
 * @param {Number} commandParamsOffset - the command parameters offset within the SMB
 * @param {Number} commandDataOffset - the command data offset within the SMB
 * @param {Object} connection - an SMBConnection instance
 * @param {Object} server - an SMBServer instance
 * @param {Function} cb callback called with the command's result
 * @param {Object} cb.result - an object with the command's result params and data
 *                             or null if the handler already sent the response and
 *                             no further processing is required by the caller
 * @param {Number} cb.result.status
 * @param {Buffer} cb.result.params
 * @param {Buffer} cb.result.data
 */
function handle(
  msg,
  commandId,
  commandParams,
  commandData,
  commandParamsOffset,
  commandDataOffset,
  connection,
  server,
  cb
) {
  // decode params
  const parser = binary.parse(commandParams)
  const paramsObj = parser
    .word16le('totalParameterCount') // bytes (not words)
    .word16le('totalDataCount')
    .word16le('maxParameterCount') // bytes (not words)
    .word16le('maxDataCount')
    .word8le('maxSetupCount')
    .skip(1) // reserved
    .word16le('flags')
    .word32le('timeout')
    .skip(2) // reserved2
    .word16le('parameterCount') // bytes (not words)
    .word16le('parameterOffset')
    .word16le('dataCount')
    .word16le('dataOffset')
    .word8le('setupCount')
    .skip(1) // reserved3
    .buffer('setup', 2 * parser.vars.setupCount).vars
  _.assign(msg, paramsObj)

  let result

  msg.subCommandId = msg.setup.readUInt16LE(0)
  const subCommand = SMB.TRANS2_SUBCOMMAND_TO_STRING[msg.subCommandId]
  if (!subCommand) {
    logger.error('encountered invalid subcommand 0x%s', msg.subCommandId.toString(16))
    result = {
      status: ntstatus.STATUS_SMB_BAD_COMMAND,
      params: utils.EMPTY_BUFFER,
      data: utils.EMPTY_BUFFER,
    }
    process.nextTick(function () {
      cb(result)
    })
    return
  }

  // decode data
  let off = 0
  msg.name = commandData[off] // not used in transaction2
  off += 1

  const subParams = msg.buf.slice(msg.parameterOffset, msg.parameterOffset + msg.parameterCount)
  const subData = msg.buf.slice(msg.dataOffset, msg.dataOffset + msg.dataCount)

  logger.debug(
    '[%s][%s] totalParameterCount: %d, parameterCount: %d, totalDataCount: %d, dataCount: %d, flags: %s',
    SMB.COMMAND_TO_STRING[commandId].toUpperCase(),
    subCommand.toUpperCase(),
    msg.totalParameterCount,
    msg.parameterCount,
    msg.totalDataCount,
    msg.dataCount,
    msg.flags.toString(2)
  )

  if (msg.parameterCount < msg.totalParameterCount || msg.dataCount < msg.totalDataCount) {
    // todo support transaction2_secondary messages (reassembling chunked transaction2 messages)
    logger.error('chunked transaction2 messages are not yet supported.')
    result = {
      status: ntstatus.STATUS_NOT_IMPLEMENTED,
      params: utils.EMPTY_BUFFER,
      data: utils.EMPTY_BUFFER,
    }
    process.nextTick(function () {
      cb(result)
    })
    return
  }

  // invoke subcommand handler
  const handler = subCmdHandlers[subCommand]
  if (handler) {
    handler(
      msg,
      msg.subCommandId,
      subParams,
      subData,
      msg.parameterOffset,
      msg.dataOffset,
      connection,
      server,
      function (result) {
        if (result.status !== ntstatus.STATUS_SUCCESS) {
          result.params = commandParams
          result.data = commandData
          cb(result)
          return
        }

        // build response

        const subParams = result.params
        const subData = result.data
        const setup = result.setup || utils.EMPTY_BUFFER

        // transaction2 response have a params length of 20 (10 words) plus length of setup
        const paramsLength = 20 + setup.length
        const dataOffset = SMB.SMB_MIN_LENGTH + paramsLength

        // calculate offsets and paddings
        let subParamsOffset, subDataOffset, pad1, pad2
        let off = dataOffset
        pad1 = utils.calculatePadLength(off, 4)
        off += pad1
        subParamsOffset = off
        off += subParams.length
        pad2 = utils.calculatePadLength(off, 4)
        off += pad2
        subDataOffset = off
        off += subData.length

        // params
        let out = put()
        out
          .word16le(subParams.length) // TotalParameterCount
          .word16le(subData.length) // TotalDataCount
          .word16le(0) // Reserved
          .word16le(subParams.length) // ParameterCount
          .word16le(subParamsOffset) // ParameterOffset
          .word16le(0) // ParameterDisplacement
          .word16le(subData.length) // DataCount
          .word16le(subDataOffset) // DataOffset
          .word16le(0) // DataDisplacement
          .word8(0) // SetupCount
          .word8(0) // Reserved2
          .put(setup) // Setup
        const params = out.buffer()

        // data
        out = put()
        out.pad(pad1).put(subParams).pad(pad2).put(subData)
        const data = out.buffer()

        // return result
        result = {
          status: ntstatus.STATUS_SUCCESS,
          params,
          data,
        }
        cb(result)
      }
    )
  } else {
    logger.error(
      "encountered unsupported subcommand 0x%s '%s'",
      msg.subCommandId.toString(16),
      subCommand.toUpperCase()
    )
    result = {
      status: ntstatus.STATUS_NOT_IMPLEMENTED,
      params: utils.EMPTY_BUFFER,
      data: utils.EMPTY_BUFFER,
    }
    cb(result)
  }
}

module.exports = handle
