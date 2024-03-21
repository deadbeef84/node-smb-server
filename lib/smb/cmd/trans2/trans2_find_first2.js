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
const logger = require('winston').loggers.get('smb')
const async = require('async')

const ntstatus = require('../../../ntstatus')
const SMB = require('../../constants')
const infoLevel = require('../../findInformationLevel')
const utils = require('../../../utils')

/**
 * TRANS2_FIND_FIRST2 (0x0001): This transaction is used to begin a search for file(s)
 * within a directory or for a directory.
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
  let off = 0
  const searchAttributes = commandParams.readUInt16LE(off)
  off += 2
  const searchCount = commandParams.readUInt16LE(off)
  off += 2
  const flags = commandParams.readUInt16LE(off)
  off += 2
  const informationLevel = commandParams.readUInt16LE(off)
  off += 2
  const searchStorageType = commandParams.readUInt32LE(off)
  off += 4
  off += utils.calculatePadLength(commandParamsOffset + off, 2) // pad to align subsequent unicode strings (utf16le) on word boundary
  const bytes = utils.extractUnicodeBytes(commandParams, off)
  off += bytes.length + 2
  const fileName = bytes.toString('utf16le')

  const includeResumeKey = !!(flags & SMB.FIND_RETURN_RESUME_KEYS)

  logger.debug(
    '[%s] searchAttributes: %s, searchCount: %d, flags: %s, informationLevel: %s, searchStorageType: %d, fileName: %s',
    SMB.TRANS2_SUBCOMMAND_TO_STRING[commandId].toUpperCase(),
    searchAttributes.toString(2),
    searchCount,
    flags.toString(2),
    SMB.FIND_INFORMATION_LEVEL_TO_STRING[informationLevel],
    searchStorageType,
    fileName
  )

  // todo evaluate/handle searchAttributes according to the CIFS spec

  let result

  const tree = server.getTree(msg.header.tid)
  if (!tree) {
    result = {
      status: ntstatus.STATUS_SMB_BAD_TID,
      params: utils.EMPTY_BUFFER,
      data: utils.EMPTY_BUFFER,
    }
    process.nextTick(function () {
      cb(result)
    })
    return
  }

  const session = server.getSession(msg.header.uid)
  if (!session) {
    result = {
      status: ntstatus.STATUS_SMB_BAD_UID,
      params: utils.EMPTY_BUFFER,
      data: utils.EMPTY_BUFFER,
    }
    process.nextTick(function () {
      cb(result)
    })
    return
  }

  let sid = 0
  let endOfSearch = 1

  function lookup(callback) {
    tree.list(fileName, callback)
  }

  function processLookupResult(files, callback) {
    if (!files.length) {
      callback(null, {
        status:
          utils.getPathName(fileName) !== '*'
            ? ntstatus.STATUS_NO_SUCH_FILE
            : ntstatus.STATUS_SUCCESS,
        params: utils.EMPTY_BUFFER,
        data: utils.EMPTY_BUFFER,
      })
      return
    }

    let count = files.length
    if (files.length > searchCount) {
      count = searchCount
      // register search
      const search = session.createSearch()
      search.results = files
      sid = search.sid
      endOfSearch = 0
    }

    const serializeResult = infoLevel.serialize(files, 0, count, informationLevel, includeResumeKey)
    if (serializeResult.status !== ntstatus.STATUS_SUCCESS) {
      callback(null, {
        status: serializeResult.status,
        params: utils.EMPTY_BUFFER,
        data: utils.EMPTY_BUFFER,
      })
      return
    }

    // build params
    const paramsOut = put()
    paramsOut
      .word16le(sid) // SID
      .word16le(count) // SearchCount
      .word16le(endOfSearch) // EndOfSearch
      .word16le(0) // EaErrorOffset
      .word16le(serializeResult.lastNameOffset) // LastNameOffset

    const params = paramsOut.buffer()
    const data = serializeResult.buffer
    result = {
      status: ntstatus.STATUS_SUCCESS,
      params,
      data,
    }
    callback(null, result)

    if (sid && flags & SMB.FIND_CLOSE_AFTER_REQUEST) {
      session.closeSearch(sid)
    }
    if (sid && endOfSearch && flags & SMB.FIND_CLOSE_AT_EOS) {
      session.closeSearch(sid)
    }
  }

  async.waterfall([lookup, processLookupResult], function (err, result) {
    if (err) {
      if (sid) {
        session.closeSearch(sid)
      }
      logger.error(err)
      cb({
        status: err.status || ntstatus.STATUS_UNSUCCESSFUL,
        params: utils.EMPTY_BUFFER,
        data: utils.EMPTY_BUFFER,
      })
    } else {
      cb(result)
    }
  })
}

module.exports = handle
