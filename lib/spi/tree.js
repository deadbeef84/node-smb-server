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

import ntstatus from '../ntstatus.js'

import SMBError from '../smberror.js'
import * as utils from '../utils.js'

/**
 * Creates an instance of Tree.
 *
 * @constructor
 * @this {Tree}
 */
class Tree {
  constructor(config) {
    this.config = config || {}
  }

  /**
   * Test whether or not the specified file exists.
   *
   * @param {String} name file name
   * @param {Function} cb callback called with the result
   * @param {SMBError} cb.error error (non-null if an error occurred)
   * @param {Boolean} cb.exists true if the file exists; false otherwise
   */
  exists(name, cb) {
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_NOT_IMPLEMENTED))
    })
  }

  /**
   * Open an existing file.
   *
   * @param {String} name file name
   * @param {Function} cb callback called with the opened file
   * @param {SMBError} cb.error error (non-null if an error occurred)
   * @param {File} cb.file opened file
   */
  open(name, cb) {
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_NOT_IMPLEMENTED))
    })
  }

  /**
   * List entries, matching a specified pattern.
   *
   * @param {String} pattern pattern
   * @param {Function} cb callback called with an array of matching files
   * @param {SMBError} cb.error error (non-null if an error occurred)
   * @param {File[]} cb.files array of matching files
   */
  list(pattern, cb) {
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_NOT_IMPLEMENTED))
    })
  }

  /**
   * Create a new file.
   *
   * @param {String} name file name
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   * @param {File} cb.file created file
   */
  createFile(name, cb) {
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_NOT_IMPLEMENTED))
    })
  }

  /**
   * Create a new directory.
   *
   * @param {String} name directory name
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   * @param {File} cb.file created directory
   */
  createDirectory(name, cb) {
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_NOT_IMPLEMENTED))
    })
  }

  /**
   * Delete a file.
   *
   * @param {String} name file name
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  delete(name, cb) {
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_NOT_IMPLEMENTED))
    })
  }

  /**
   * Delete a directory. It must be empty in order to be deleted.
   *
   * @param {String} name directory name
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  deleteDirectory(name, cb) {
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_NOT_IMPLEMENTED))
    })
  }

  /**
   * Rename a file or directory.
   *
   * @param {String} oldName old name
   * @param {String} newName new name
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  rename(oldName, newName, cb) {
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_NOT_IMPLEMENTED))
    })
  }

  /**
   * Refresh a specific folder.
   *
   * @param {String} folderPath
   * @param {Boolean} deep
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  refresh(folderPath, deep, cb) {
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_NOT_IMPLEMENTED))
    })
  }

  /**
   * Disconnect this tree.
   *
   * @param {Function} cb callback called on completion
   * @param {SMBError} cb.error error (non-null if an error occurred)
   */
  disconnect(cb) {
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_NOT_IMPLEMENTED))
    })
  }

  /**
   * Normalizes a unicode string in order to avoid issues related to different code points.
   * @param {String} str The value to be normalized.
   * @returns {String} A normalized string value.
   */
  unicodeNormalize(str) {
    if (!this.config.noUnicodeNormalize) {
      return utils.unicodeNormalize(str)
    } else {
      return str
    }
  }

  /**
   * Determines if two strings are equal based on their normalized unicode values.
   * @param {String} str1 The first value to be compared.
   * @param {String} str2 The second value to be compared.
   * @returns {Boolean} true if the two values are equal, otherwise false.
   */
  unicodeEquals(str1, str2) {
    if (!this.config.noUnicodeNormalize) {
      return utils.unicodeEquals(str1, str2)
    } else {
      return str1 == str2
    }
  }

  /**
   * Clears the tree's cache. Default implementation does nothing.
   * @param {function} cb Will be invoked when the operation is complete.
   * @param {string|Error} cb.err Will be truthy if there were errors during the operation.
   */
  clearCache(cb) {
    cb()
  }
}

export default Tree
