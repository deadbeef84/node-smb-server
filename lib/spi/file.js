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

import Path from 'node:path'

import async from 'async'
import ntstatus from '../ntstatus.js'
import SMBError from '../smberror.js'
import * as utils from '../utils.js'

/**
 * Creates an instance of File.
 *
 * @constructor
 * @this {File}
 * @param {String} filePath normalized file path
 * @param {Tree} tree tree object
 */
class File {
  constructor(filePath, tree) {
    this.filePath = tree.unicodeNormalize(filePath)
    this.fileName = utils.getPathName(this.filePath)
    this.tree = tree
  }

  /**
   * Return the Tree.
   *
   * @return {String} file path
   */
  getTree() {
    return this.tree
  }

  /**
   * Return the normalized file path.
   *
   * @return {String} file path
   */
  getPath() {
    return this.filePath
  }

  /**
   * Return the file name.
   *
   * @return {String} file name
   */
  getName() {
    return this.fileName
  }

  /**
   * Return a flag indicating whether this is a file.
   *
   * @return {Boolean} <code>true</code> if this is a file;
   *         <code>false</code> otherwise
   */
  isFile() {
    throw new Error('abstract method')
  }

  /**
   * Return a flag indicating whether this is a directory.
   *
   * @return {Boolean} <code>true</code> if this is a directory;
   *         <code>false</code> otherwise
   */
  isDirectory() {
    throw new Error('abstract method')
  }

  /**
   * Return a flag indicating whether this file is read-only.
   *
   * @return {Boolean} <code>true</code> if this file is read-only;
   *         <code>false</code> otherwise
   */
  isReadOnly() {
    throw new Error('abstract method')
  }

  /**
   * Converts the file into a generic object suitable for transport outside of the backend.
   *
   * @return {object} An object containing information about the file.
   */
  toObject() {
    return {
      name: this.getName(),
      path: utils.getParentPath(this.getPath()),
      isFolder: this.isDirectory(),
    }
  }

  /**
   * Return a flag indicating whether this file is hidden.
   *
   * @return {Boolean} <code>true</code> if this file is hidden;
   *         <code>false</code> otherwise
   */
  isHidden() {
    const name = this.getName()
    return name.length && (name[0] === '.' || name[0] === '~')
  }

  /**
   * Return the file size.
   *
   * @return {Number} file size, in bytes
   */
  size() {
    throw new Error('abstract method')
  }

  /**
   * Return the number of bytes that are allocated to the file.
   *
   * @return {Number} allocation size, in bytes
   */
  allocationSize() {
    throw new Error('abstract method')
  }

  /**
   * Return the time of last modification, in milliseconds since
   * Jan 1, 1970, 00:00:00.0.
   *
   * @return {Number} time of last modification
   */
  lastModified() {
    throw new Error('abstract method')
  }

  /**
   * Sets the time of last modification, in milliseconds since
   * Jan 1, 1970, 00:00:00.0.
   *
   * @param {Number} ms
   * @return {Number} time of last modification
   */
  setLastModified(ms) {
    throw new Error('abstract method')
  }

  /**
   * Return the time when file status was last changed, in milliseconds since
   * Jan 1, 1970, 00:00:00.0.
   *
   * @return {Number} when file status was last changed
   */
  lastChanged() {
    throw new Error('abstract method')
  }

  /**
   * Return the create time, in seconds since Jan 1, 1970, 00:00:00.0.
   * Jan 1, 1970, 00:00:00.0.
   *
   * @return {Number} time created
   */
  created() {
    throw new Error('abstract method')
  }

  /**
   * Return the time of last access, in seconds since Jan 1, 1970, 00:00:00.0.
   * Jan 1, 1970, 00:00:00.0.
   *
   * @return {Number} time of last access
   */
  lastAccessed() {
    throw new Error('abstract method')
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
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_NOT_IMPLEMENTED))
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
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_NOT_IMPLEMENTED))
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
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_NOT_IMPLEMENTED))
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
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_NOT_IMPLEMENTED))
    })
  }

  /**
   * Flush the contents of the file to disk.
   *
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  flush(cb) {
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_NOT_IMPLEMENTED))
    })
  }

  /**
   * Close this file, releasing any resources.
   *
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  close(cb) {
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_NOT_IMPLEMENTED))
    })
  }

  /**
   * Copies this file to another tree
   * @param {Tree} destTree destination tree
   * @param {String} destName name of destination file
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  copyTo(destTree, destName, cb) {
    const self = this
    const createFn = this.isFile() ? destTree.createFile : destTree.createDirectory
    createFn.call(destTree, destName, function (err, destFile) {
      if (err) {
        cb(err)
      } else {
        copy(self, destFile, false, function (err) {
          destFile.close(function (ignored) {
            cb(err)
          })
        })
      }
    })
  }

  /**
   * Moves this file to another tree
   * @param {Tree} destTree destination tree
   * @param {String} destName name of destination file
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  moveTo(destTree, destName, cb) {
    const self = this
    const createFn = this.isFile() ? destTree.createFile : destTree.createDirectory
    createFn.call(destTree, destName, function (err, destFile) {
      if (err) {
        cb(err)
      } else {
        copy(self, destFile, true, function (err) {
          destFile.close(function (ignored) {
            cb(err)
          })
        })
      }
    })
  }
}

/**
 * Recursive copy/move helper function
 *
 * @param {File} srcFile
 * @param {File} destFile
 * @param {Boolean} deleteSrc if true the result is a move (i.e. copy & delete)
 * @param {Function} cb callback called on completion
 * @param {SMBError} cb.error error (non-null if an error occurred)
 */
function copy(srcFile, destFile, deleteSrc, cb) {
  if (srcFile.isFile()) {
    // file: copy single file
    const srcLength = srcFile.size()
    const buf = Buffer.alloc(Math.min(0xffff, srcLength))
    let read = 0
    async.whilst(
      function () {
        return read < srcLength
      },
      function (callback) {
        srcFile.read(buf, 0, buf.length, read, function (err, bytesRead, data) {
          if (err || !bytesRead) {
            callback(err)
            return
          }
          data = bytesRead < data.length ? data.slice(0, bytesRead) : data
          destFile.write(data, read, function (err) {
            if (!err) {
              read += bytesRead
            }
            callback(err)
          })
        })
      },
      function (err) {
        if (err) {
          cb(err)
          return
        }
        // flush & close dest file, close src file
        async.series(
          [
            function (callback) {
              destFile.flush(callback)
            },
            function (callback) {
              destFile.close(callback)
            },
            function (callback) {
              srcFile.close(callback)
            },
            function (callback) {
              if (deleteSrc) {
                srcFile.delete(callback)
              } else {
                // noop
                callback()
              }
            },
          ],
          function (err) {
            cb(err)
          }
        )
      }
    )
  } else {
    // directory: list src files and copy recursively
    const pattern = srcFile.getPath() + '/*'
    srcFile.getTree().list(pattern, function (err, files) {
      if (err) {
        cb(err)
        return
      }
      async.each(
        files,
        function (file, callback) {
          // create dest file
          const destPath = Path.join(destFile.getPath(), file.getName())
          const destTree = destFile.getTree()
          const createFn = file.isFile() ? destTree.createFile : destTree.createDirectory
          createFn.call(destTree, destPath, function (err, destFile) {
            if (err) {
              callback(err)
            } else {
              // recurse
              copy(file, destFile, deleteSrc, function (err) {
                destFile.close(function (ignored) {
                  callback(err)
                })
              })
            }
          })
        },
        function (err) {
          if (err) {
            cb(err)
            return
          }
          if (deleteSrc) {
            srcFile.delete(cb)
          } else {
            cb()
          }
        }
      )
    })
  }
}

export default File
