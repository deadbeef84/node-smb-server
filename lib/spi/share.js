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
import { EventEmitter } from 'node:events'
import util from 'node:util'

/**
 * Creates an instance of Share.
 *
 * @constructor
 * @this {Share}
 * @param {String} name share name
 * @param {Object} config configuration hash
 */
class Share extends EventEmitter {
  constructor(name, config) {
    // call the super constructor to initialize `this`
    super()

    this.config = config || {}
    this.name = name
    this.description = this.config.description || ''
  }

  /**
   * Retrieves an array of event names that the share provides.
   *
   * @return {Array} The names of events (as strings) that the share emits.
   */
  getEvents() {
    if (this.config.events) {
      return this.config.events
    } else {
      return []
    }
  }

  /**
   * Return a flag indicating whether this is a named pipe share.
   *
   * @return {Boolean} <code>true</code> if this is a named pipe share;
   *         <code>false</code> otherwise, i.e. if it is a disk share.
   */
  isNamedPipe() {
    return false
  }

  /**
   *
   * @param {Session} session
   * @param {Buffer|String} shareLevelPassword optional share-level password (may be null)
   * @param {Function} cb callback called with the connect tree
   * @param {SMBError} cb.error error (non-null if an error occurred)
   * @param {Tree} cb.tree connected tree
   */
  connect(session, shareLevelPassword, cb) {
    process.nextTick(function () {
      cb(new SMBError(ntstatus.STATUS_NOT_IMPLEMENTED))
    })
  }
}

export default Share
