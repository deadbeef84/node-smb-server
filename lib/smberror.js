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

import errno from 'errno'

import ntstatus from './ntstatus.js'

/**
 * Represents an SMB Error.
 *
 * @param {Number} status
 * @param {String} [message]
 * @constructor
 */
class SMBError {
  constructor(status, message) {
    this.status = status
    this.message = message || ntstatus.STATUS_TO_STRING[status] || 'unknown error'
  }

  static fromSystemError(err, message) {
    let status = ntstatus.STATUS_UNSUCCESSFUL
    let msg = err

    if (typeof msg !== 'string') {
      msg = err.message || ntstatus.STATUS_TO_STRING[status] || 'unknown error'

      /**
       * err.syscall
       * err.errno
       * err.code
       * err.path
       */
      if (err.errno || err.code) {
        let code = err.code
        if (errno.errno[err.errno]) {
          msg = errno.errno[err.errno].description
          code = errno.errno[err.errno].code
        }
        if (err.path) {
          msg += ' [' + err.path + ']'
        }
        // the code:errno mapping is not unique (see e.g. 'ENOENT') ...
        switch (code) {
          case 'EINVAL':
            status = ntstatus.STATUS_NOT_IMPLEMENTED
            break
          case 'ENOENT':
            status = ntstatus.STATUS_NO_SUCH_FILE
            break
          case 'EPERM':
            status = ntstatus.STATUS_ACCESS_DENIED
            break
          case 'EBADF':
            // status = ntstatus.STATUS_INVALID_HANDLE;
            status = ntstatus.STATUS_SMB_BAD_FID
            break
          case 'EOF':
            status = ntstatus.STATUS_END_OF_FILE
            break
          case 'EEXIST':
            status = ntstatus.STATUS_OBJECT_NAME_COLLISION
            break
          case 'EACCES':
            status = ntstatus.STATUS_NETWORK_ACCESS_DENIED
            break
        }
      }
    }
    if (message) {
      msg += ' [' + message + ']'
    }

    return new SMBError(status, msg)
  }

  static systemToSMBErrorTranslator(cb, message) {
    return function () {
      const args = []
      if (arguments.length) {
        // first parameter of callback is the error parameter
        const err = arguments[0]
        args.push(err ? SMBError.fromSystemError(err, message) : null)
        for (let i = 1; i < arguments.length; i++) {
          args.push(arguments[i])
        }
      }
      cb.apply(this, args)
    }
  }

  toString() {
    this.status = this.status || ntstatus.STATUS_UNSUCCESSFUL
    return '[' + this.status + '] (' + ntstatus.STATUS_TO_STRING[this.status] + ')' + this.message
  }
}

export default SMBError
