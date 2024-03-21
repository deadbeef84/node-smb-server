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

import SMBTree from './smbtree.js'

/**
 * Represents an active share exposed by this SMB server.
 *
 * @param {SMBServer} smbServer
 * @param {Share} spiShare
 * @constructor
 */
class SMBShare {
  constructor(smbServer, spiShare) {
    this.smbServer = smbServer
    this.spiShare = spiShare
  }

  getName() {
    return this.spiShare.name
  }

  getDescription() {
    return this.spiShare.description
  }

  getEvents() {
    return this.spiShare.getEvents()
  }

  on(eventName, cb) {
    this.spiShare.on(eventName, cb)
  }

  /**
   * Return a flag indicating whether this is a named pipe share.
   *
   * @return {Boolean} <code>true</code> if this is a named pipe share;
   *         <code>false</code> otherwise, i.e. if it is a disk share.
   */
  isNamedPipe() {
    return this.spiShare.isNamedPipe()
  }

  /**
   *
   * @param {Session} session
   * @param {Buffer|String} shareLevelPassword optional share-level password (may be null)
   * @param {Function} cb callback called with the connect tree
   * @param {SMBError} cb.error error (non-null if an error occurred)
   * @param {SMBTree} cb.tree connected tree
   */
  connect(session, shareLevelPassword, cb) {
    const self = this
    this.spiShare.connect(session, shareLevelPassword, function (err, tree) {
      if (err) {
        cb(err)
      } else {
        cb(null, new SMBTree(self.smbServer, self, tree))
      }
    })
  }
}

export default SMBShare
