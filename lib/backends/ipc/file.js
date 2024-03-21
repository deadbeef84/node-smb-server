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

import util from 'node:util'

import baseLogger from '../../logger.js'

import File from '../../spi/file.js'
import SMBError from '../../smberror.js'
import ntstatus from '../../ntstatus.js'
const logger = baseLogger.child({ module: 'spi' })

/**
 * Creates an instance of File.
 *
 * @constructor
 * @private
 * @this {IPCFile}
 * @param {String} filePath normalized file path
 * @param {IPCTree} tree tree object
 */
class IPCFile extends File {
  constructor(filePath, tree) {
    logger.debug('[ipc] file.open %s', filePath)
    this.writeable = true

    super(filePath, tree)
  }

  // ---------------------------------------------------------------------< File >
  /**
   * Return a flag indicating whether this is a file.
   *
   * @return {Boolean} <code>true</code> if this is a file;
   *         <code>false</code> otherwise
   */
  isFile() {
    return true
  }

  /**
   * Return a flag indicating whether this is a directory.
   *
   * @return {Boolean} <code>true</code> if this is a directory;
   *         <code>false</code> otherwise
   */
  isDirectory() {
    return false
  }

  /**
   * Return a flag indicating whether this file is read-only.
   *
   * @return {Boolean} <code>true</code> if this file is read-only;
   *         <code>false</code> otherwise
   */
  isReadOnly() {
    return !this.writeable
  }

  /**
   * Return the file size.
   *
   * @return {Number} file size, in bytes
   */
  size() {
    return 0
  }

  /**
   * Return the number of bytes that are allocated to the file.
   *
   * @return {Number} allocation size, in bytes
   */
  allocationSize() {
    return 0
  }

  /**
   * Return the time of last modification, in milliseconds since
   * Jan 1, 1970, 00:00:00.0.
   *
   * @return {Number} time of last modification
   */
  lastModified() {
    return 0
  }

  /**
   * Sets the time of last modification, in milliseconds since
   * Jan 1, 1970, 00:00:00.0.
   *
   * @param {Number} ms
   * @return {Number} time of last modification
   */
  setLastModified(ms) {
    // ignoring ...
  }

  /**
   * Return the time when file status was last changed, in milliseconds since
   * Jan 1, 1970, 00:00:00.0.
   *
   * @return {Number} when file status was last changed
   */
  lastChanged() {
    return this.lastModified()
  }

  /**
   * Return the create time, in milliseconds since Jan 1, 1970, 00:00:00.0.
   * Jan 1, 1970, 00:00:00.0.
   *
   * @return {Number} time created
   */
  created() {
    return 0
  }

  /**
   * Return the time of last access, in milliseconds since Jan 1, 1970, 00:00:00.0.
   * Jan 1, 1970, 00:00:00.0.
   *
   * @return {Number} time of last access
   */
  lastAccessed() {
    return 0
  }

  /**
   * Read bytes at a certain position inside the file.
   *
   * @param {Buffer} buffer the buffer that the data will be written to
   * @param {Number} offset the offset in the buffer to start writing at
   * @param {Number} length the number of bytes to read
   * @param {Number} position offset where to begin reading from in the file
   * @param {Function} cb callback called with the bytes actually read
   * @param {SMBError} cb.error error (non-null if an error occurred)
   * @param {Number} cb.bytesRead number of bytes actually read
   * @param {Buffer} cb.buffer buffer holding the bytes actually read
   */
  read(buffer, offset, length, position, cb) {
    logger.debug(
      '[ipc] file.read %s offset=%d, length=%d, position=%d',
      this.filePath,
      offset,
      length,
      position
    )
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_SMB_NO_SUPPORT))
    })
  }

  /**
   * Write bytes at a certain position inside the file.
   *
   * @param {Buffer} data buffer to write
   * @param {Number} position position inside file
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  write(data, position, cb) {
    logger.debug(
      '[ipc] file.write %s data.length=%d, position=%d',
      this.filePath,
      data.length,
      position
    )
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_SMB_NO_SUPPORT))
    })
  }

  /**
   * Sets the file length.
   *
   * @param {Number} length file length
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  setLength(length, cb) {
    logger.debug('[ipc] file.setLength %s length=%d', this.filePath, length)
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_SMB_NO_SUPPORT))
    })
  }

  /**
   * Delete this file or directory. If this file denotes a directory, it must
   * be empty in order to be deleted.
   *
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  delete(cb) {
    logger.debug('[ipc] file.delete %s', this.filePath)
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_SMB_NO_SUPPORT))
    })
  }

  /**
   * Flush the contents of the file to disk.
   *
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  flush(cb) {
    logger.debug('[ipc] file.flush %s', this.filePath)
    // there's nothing to do here
    process.nextTick(function () {
      cb()
    })
  }

  /**
   * Close this file, releasing any resources.
   *
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  close(cb) {
    logger.debug('[ipc] file.close %s', this.filePath)
    // there's nothing to do here
    process.nextTick(function () {
      cb()
    })
  }
}

export default IPCFile
