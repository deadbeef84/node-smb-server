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

import Share from '../../spi/share.js'
import IPCTree from './tree.js'

/**
 * Creates an instance of IPCShare.
 *
 * @constructor
 * @this {IPCShare}
 * @param {String} name share name
 * @param {Object} config configuration hash
 */
class IPCShare extends Share {
  constructor(name, config) {
    config = config || {}

    super(name, config)

    this.description = config.description || 'Remote IPC'
  }

  /**
   * Return a flag indicating whether this is a named pipe share.
   *
   * @return {Boolean} <code>true</code> if this is a named pipe share;
   *         <code>false</code> otherwise, i.e. if it is a disk share.
   */
  isNamedPipe() {
    return true
  }

  /**
   *
   * @param {Session} session
   * @param {Buffer|String} shareLevelPassword optional share-level password (may be null)
   * @param {Function} cb callback called with the connect tree
   * @param {String|Error} cb.error error (non-null if an error occurred)
   * @param {IPCTree} cb.tree connected tree
   */
  connect(session, shareLevelPassword, cb) {
    const self = this
    process.nextTick(function () {
      cb(null, new IPCTree(self))
    })
  }
}

export default IPCShare
