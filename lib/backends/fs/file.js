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

import fs from 'node:fs'
import Path from 'node:path'

import baseLogger from '../../logger.js'

import async from 'async'
import File from '../../spi/file.js'
import SMBError from '../../smberror.js'
const logger = baseLogger.child({ module: 'spi' })
const perflog = baseLogger.child({ module: 'perf' })

/**
 * Creates an instance of File.
 *
 * @constructor
 * @private
 * @this {FSFile}
 * @param {String} filePath normalized file path
 * @param {fs.Stats} stats fs.Stats object
 * @param {FSTree} tree tree object
 */
class FSFile extends File {
  constructor(filePath, stats, tree) {
    logger.debug('[fs] file.open %s', filePath)
    this.stats = stats
    this.realPath = Path.join(tree.share.path, filePath)
    // extract file permissions from stats.mode, convert to octagonal, check if owner write permission bit is set (00200)
    // see http://stackoverflow.com/questions/11775884/nodejs-file-permissions
    this.writeable = !!(2 & parseInt((stats.mode & parseInt('777', 8)).toString(8)[0]))

    super(filePath, tree)
  }

  /**
   * Async factory method
   *
   * @param {String} filePath normalized file path
   * @param {FSTree} tree tree object
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   * @param {FSFile} cb.file FSFile instance
   */
  static createInstance(filePath, tree, cb) {
    const realPath = Path.join(tree.share.path, filePath)
    fs.stat(realPath, function (err, stats) {
      if (err) {
        cb(
          SMBError.fromSystemError(err, 'unable to create file due to unexpected error ' + filePath)
        )
      } else {
        cb(null, new FSFile(filePath, stats, tree))
      }
    })
  }

  /**
   * Refreshes the stats information of the underlying file.
   *
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  refreshStats(cb) {
    const self = this
    // update stats
    perflog.debug('%s File.refreshStats.fs.stat', this.filePath)
    // todo use fs.fstat if there's an open file descriptor?
    fs.stat(this.realPath, function (ignored, stats) {
      if (!ignored) {
        self.stats = stats
      } else {
        logger.warn('[fs] file.refreshStats %s failed', self.filePath, ignored)
      }
      cb()
    })
  }

  /**
   * Sets the read-only value of the file if needed.
   *
   * @param {Boolean} readOnly If TRUE, file will be read only; otherwise, file will be writable. *
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  setReadOnly(readOnly, cb) {
    const self = this
    if (self.isReadOnly() != readOnly) {
      logger.debug('[fs] setReadOnly %s %s', readOnly, self.filePath)
      const self = this
      fs.chmod(self.realPath, readOnly ? '444' : '644', function (err) {
        if (err) {
          cb(
            SMBError.fromSystemError(
              err,
              'unable to set read only status due to unepxected error ' + self.filePath
            )
          )
        } else {
          self.writeable = !readOnly
          cb()
        }
      })
    } else {
      cb()
    }
  }

  getDescriptor(cb) {
    logger.debug('[fs] getDescriptor %s', this.filePath)
    const self = this

    function openCB(err, fd) {
      if (err) {
        cb(
          SMBError.fromSystemError(
            err,
            'unable to get file descriptor due to unexpeced error ' + self.filePath
          )
        )
      } else {
        self.fd = fd
        cb(null, fd)
      }
    }

    if (this.fd) {
      cb(null, this.fd)
    } else {
      // open read-write
      fs.open(this.realPath, 'r+', function (err, fd) {
        if (err && err.code === 'EACCES') {
          // open read-only
          logger.debug('[fs] getDescriptor file is read-only', self.filePath)
          fs.open(self.realPath, 'r', openCB)
        } else {
          openCB(err, fd)
        }
      })
    }
  }

  // ---------------------------------------------------------------------< File >
  /**
   * Return a flag indicating whether this is a file.
   *
   * @return {Boolean} <code>true</code> if this is a file;
   *         <code>false</code> otherwise
   */
  isFile() {
    return this.stats.isFile()
  }

  /**
   * Return a flag indicating whether this is a directory.
   *
   * @return {Boolean} <code>true</code> if this is a directory;
   *         <code>false</code> otherwise
   */
  isDirectory() {
    return this.stats.isDirectory()
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
    logger.debug('[fs] size %s (%d bytes)', this.filePath, this.stats.size)
    return this.stats.size
  }

  /**
   * Return the number of bytes that are allocated to the file.
   *
   * @return {Number} allocation size, in bytes
   */
  allocationSize() {
    const size = this.stats.blocks * this.stats.blksize
    logger.debug('[fs] allocationSize %s (%d bytes)', this.filePath, size)
    return size
  }

  /**
   * Return the time of last modification, in milliseconds since
   * Jan 1, 1970, 00:00:00.0.
   *
   * @return {Number} time of last modification
   */
  lastModified() {
    return this.stats.mtime.getTime()
  }

  /**
   * Sets the time of last modification, in milliseconds since
   * Jan 1, 1970, 00:00:00.0.
   *
   * @param {Number} ms
   * @return {Number} time of last modification
   */
  setLastModified(ms) {
    // cheatin' ...
    this.stats.mtime = new Date(ms)
  }

  /**
   * Return the time when file status was last changed, in milliseconds since
   * Jan 1, 1970, 00:00:00.0.
   *
   * @return {Number} when file status was last changed
   */
  lastChanged() {
    return this.stats.ctime.getTime()
  }

  /**
   * Return the create time, in milliseconds since Jan 1, 1970, 00:00:00.0.
   * Jan 1, 1970, 00:00:00.0.
   *
   * @return {Number} time created
   */
  created() {
    if (this.stats.birthtime) {
      // node >= v0.12
      return this.stats.birthtime.getTime()
    } else {
      return this.stats.ctime.getTime()
    }
  }

  /**
   * Return the time of last access, in milliseconds since Jan 1, 1970, 00:00:00.0.
   * Jan 1, 1970, 00:00:00.0.
   *
   * @return {Number} time of last access
   */
  lastAccessed() {
    return this.stats.atime.getTime()
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
      '[fs] file.read %s offset=%d, length=%d, position=%d',
      this.filePath,
      offset,
      length,
      position
    )
    const self = this

    async.waterfall(
      [
        function (done) {
          self.getDescriptor(done)
        },
        function (fd, done) {
          perflog.debug('%s File.read.fs.read %d', self.filePath, length)
          fs.read(
            fd,
            buffer,
            offset,
            length,
            position,
            SMBError.systemToSMBErrorTranslator(
              done,
              'unable to read file due to unexpected error ' + self.filePath
            )
          )
        },
      ],
      cb
    )
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
      '[fs] file.write %s data.length=%d, position=%d',
      this.filePath,
      data.length,
      position
    )
    const self = this

    async.waterfall(
      [
        function (done) {
          self.getDescriptor(done)
        },
        function (fd, done) {
          perflog.debug('%s File.write.fs.write %d', self.getPath(), data.length)
          fs.write(
            fd,
            data,
            0,
            data.length,
            position,
            SMBError.systemToSMBErrorTranslator(
              done,
              'unable to write file due to unexpected error ' + self.filePath
            )
          )
        },
      ],
      cb
    )
  }

  /**
   * Sets the file length.
   *
   * @param {Number} length file length
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  setLength(length, cb) {
    logger.debug('[fs] file.setLength %s length=%d', this.filePath, length)
    const self = this

    async.series(
      [
        function (done) {
          // first close the file if needed
          self.close(done)
        },
        function (done) {
          // truncate underlying file
          perflog.debug('%s File.setLength.fs.truncate %d', self.getPath(), length)
          fs.truncate(
            self.realPath,
            length,
            SMBError.systemToSMBErrorTranslator(
              done,
              'unable to set file length due to unexpected error ' + self.filePath
            )
          )
        },
        function (done) {
          // update stats
          self.refreshStats(done)
        },
      ],
      cb
    )
  }

  /**
   * Delete this file or directory. If this file denotes a directory, it must
   * be empty in order to be deleted.
   *
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  delete(cb) {
    logger.debug('[fs] file.delete %s', this.filePath)
    const self = this

    async.series(
      [
        function (done) {
          // first close the file if needed
          self.close(done)
        },
        function (done) {
          // delete underlying file/directory
          if (self.isDirectory()) {
            perflog.debug('%s File.delete.fs.rmdir', self.getPath())
            fs.rmdir(
              self.realPath,
              SMBError.systemToSMBErrorTranslator(
                done,
                'unable to delete directory due to unexpected error ' + self.filePath
              )
            )
          } else {
            perflog.debug('%s File.delete.fs.unlink', self.getPath())
            fs.unlink(
              self.realPath,
              SMBError.systemToSMBErrorTranslator(
                done,
                'unable to delete file due to unexpected error ' + self.filePath
              )
            )
          }
        },
      ],
      cb
    )
  }

  /**
   * Flush the contents of the file to disk.
   *
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  flush(cb) {
    logger.debug('[fs] file.flush %s', this.filePath)
    const self = this

    if (this.fd) {
      async.series(
        [
          function (done) {
            // flush modified file buffers to disk
            perflog.debug('%s File.flush.fs.fsync', self.getPath())
            fs.fsync(
              self.fd,
              SMBError.systemToSMBErrorTranslator(
                done,
                'unable to flush file due to unexpected error ' + self.filePath
              )
            )
          },
          function (done) {
            // update stats
            self.refreshStats(done)
          },
        ],
        cb
      )
    } else {
      cb()
    }
  }

  /**
   * Close this file, releasing any resources.
   *
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  close(cb) {
    logger.debug('[fs] file.close %s', this.filePath)
    const callback = SMBError.systemToSMBErrorTranslator(
      cb,
      'unable to close file due to unexpected error ' + this.filePath
    )

    const self = this
    // close file descriptor if needed
    if (self.fd) {
      perflog.debug('%s File.close.fs.close', self.getPath())
      fs.close(self.fd, function (err) {
        self.fd = undefined
        callback(err)
      })
    } else {
      // nothing to do
      callback()
    }
  }
}

export default FSFile
