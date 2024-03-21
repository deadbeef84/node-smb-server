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

import os from 'node:os'

import net from 'node:net'
import { EventEmitter } from 'node:events'
import util from 'node:util'

import baseLogger from './logger.js'

import _ from 'lodash'
import async from 'async'
import common from './common.js'
import * as utils from './utils.js'
import DefaultAuthenticator from './defaultauthenticator.js'
import * as ntlm from './ntlm.js'
import SMBConnection from './smbconnection.js'
import SMBLogin from './smblogin.js'
import SMBSession from './smbsession.js'
import SMBShare from './smbshare.js'
import IPCShare from './backends/ipc/share.js'
import FSShare from './backends/fs/share.js'
const logger = baseLogger.child({ module: 'default' })

/**
 * SMB Server
 *
 * events:
 * - error: error
 * - started
 * - terminated
 * - shareConnected: shareName
 * - shareDisconnected: shareName
 * - fileCreated: shareName, path
 * - folderCreated: shareName, path
 * - fileDeleted: shareName, path
 * - folderDeleted: shareName, path
 * - itemMoved: shareName, oldPath, newPath
 * - folderListed: shareName, path
 *
 * @param {Object} config - configuration hash
 * @param {Authenticator} authenticator
 * @constructor
 */
class SMBServer extends EventEmitter {
  constructor(config, authenticator) {
    // call the super constructor to initialize `this`
    super()

    this.tcpServer = net.createServer()
    this.connections = {}
    this.logins = {}
    this.sessions = {}
    this.shares = {}
    this.trees = {}
    // todo load/persist generated server guid
    this.guid = utils.generateRawUUID()
    this.domainName = (config && config.domainName) || ''
    this.hostName = os.hostname()
    this.nativeOS = os.type() + ' ' + os.release()
    this.nativeLanMan = common.NATIVE_LANMAN
    this.config = (config && _.cloneDeep(config)) || {}
    this.authenticator = authenticator || new DefaultAuthenticator(config)
    // init shares
    const self = this
    _.forEach(config.shares, function (shareCfg, name) {
      const type = shareCfg.backend
      const Share = type === 'fs' ? FSShare : type === 'ipc' ? IPCShare : null
      name = name.toUpperCase() // share names are uppercase
      const share = new SMBShare(self, new Share(name, shareCfg))
      self.shares[name] = share
      const shareEvents = share.getEvents()

      const forwardEvent = function (eventName) {
        share.on(eventName, function (arg) {
          logger.debug(
            '%d: received %s event from share. forwarding',
            new Date().getTime(),
            eventName
          )
          self.emit(eventName, arg)
        })
      }

      for (let i = 0; i < shareEvents.length; i++) {
        logger.debug('registering share %s event', shareEvents[i])
        forwardEvent(shareEvents[i])
      }
    })
    // add IPC$ share
    this.shares.IPC$ = new SMBShare(this, new IPCShare('IPC$', {}))

    this.tcpServer.on('connection', function (socket) {
      socket.setNoDelay(true)
      socket.id = ++SMBServer.connectionIdCounter

      logger.info(
        'established client connection #%d from [%s:%d] -> [%s:%d]',
        socket.id,
        socket.remoteAddress,
        socket.remotePort,
        socket.localAddress,
        socket.localPort
      )

      // setup socket event handlers
      socket.on('end', function () {
        logger.info(
          'client #%d disconnected (received: %dkb, sent: %dkb)',
          socket.id,
          Math.floor(socket.bytesRead / 1000),
          Math.floor(socket.bytesWritten / 1000)
        )
      })

      socket.on('error', function (err) {
        logger.info(
          'client #%d [%s:%d] connection error',
          socket.id,
          socket.remoteAddress,
          socket.remotePort,
          err
        )
        logger.error(err)
      })

      socket.on('close', function (hadError) {
        delete self.connections[socket.id]
      })

      // create a new SMBConnection instance per tcp socket connection
      self.connections[socket.id] = new SMBConnection(socket, self)
    })

    this.tcpServer.on('error', this.onError.bind(this))
    this.tcpServer.on('close', this.onClose.bind(this))
  }

  onError(err) {
    logger.error(err)
    this.emit('error', err)
  }

  onClose() {
    logger.info('[%s] SMB server stopped', process.pid)
    this.emit('terminated')
  }

  start(port, host, cb) {
    const self = this
    this.tcpServer.listen(port, host, function () {
      const realPort = this.address().port
      logger.info('[%s] SMB server started listening on port %d', process.pid, realPort)
      self.emit('started')
      self.tsStarted = Date.now()
      cb()
    })
  }

  stop(cb) {
    this.tcpServer.close(function (err) {
      if (err) {
        logger.error(err)
      }
      cb(err)
    })
  }

  getGuid() {
    return this.guid
  }

  getStartTime() {
    return this.tsStarted
  }

  createLogin() {
    const login = new SMBLogin(this, ntlm.createChallenge())
    // register login
    this.logins[login.key] = login
    return login
  }

  getLogin(key) {
    return this.logins[key]
  }

  destroyLogin(key) {
    delete this.logins[key]
  }

  /**
   *
   * @param {SMBLogin} login
   * @param {String} accountName
   * @param {String} primaryDomain
   * @param {Buffer} caseInsensitivePassword
   * @param {Buffer} caseSensitivePassword
   * @param {Function} cb callback called with the authenticated session
   * @param {String|Error} cb.error error (non-null if an error occurred)
   * @param {SMBSession} cb.session authenticated session
   */
  setupSession(
    login,
    accountName,
    primaryDomain,
    caseInsensitivePassword,
    caseSensitivePassword,
    cb
  ) {
    const self = this
    this.authenticator.authenticate(
      login.challenge,
      caseInsensitivePassword,
      caseSensitivePassword,
      primaryDomain,
      accountName,
      function (err, session) {
        if (err) {
          cb(err)
          return
        }
        const smbSession = new SMBSession(self, accountName, primaryDomain, session)
        // register session
        self.sessions[smbSession.uid] = smbSession
        cb(null, smbSession)
      }
    )
  }

  getSession(uid) {
    return this.sessions[uid]
  }

  destroySession(uid) {
    delete this.sessions[uid]
  }

  getShareNames() {
    return _.keys(this.shares)
  }

  listShares() {
    const result = []
    _.forEach(this.shares, function (share, nm) {
      result.push({ name: share.getName(), description: share.getDescription() })
    })
    return result
  }

  /**
   * Refresh a specific folder on a specific share.
   *
   * @param {String} shareName
   * @param {String} folderPath
   * @param {Boolean} deep
   * @param {Function} cb callback called on completion
   * @param {String|Error} cb.error error (non-null if an error occurred)
   */
  refresh(shareName, folderPath, deep, cb) {
    // share names are uppercase
    shareName = shareName.toUpperCase()

    if (!this.shares[shareName]) {
      process.nextTick(function () {
        cb(new Error('share not found'))
      })
      return
    }

    // walk connected trees and find tree associated with specified share
    let tree = null
    _.forOwn(this.trees, function (t) {
      if (t.getShare().getName() === shareName) {
        // found matching connected share
        tree = t
        return false
      }
    })

    if (!tree) {
      process.nextTick(function () {
        cb(new Error('share not connected'))
      })
      return
    }

    tree.refresh(folderPath, deep, cb)
  }

  /**
   *
   * @param {SMBSession} session
   * @param {String} shareName
   * @param {Buffer|String} shareLevelPassword optional share-level password (may be null)
   * @param {Function} cb callback called with the connect tree
   * @param {String|Error} cb.error error (non-null if an error occurred)
   * @param {SMBSession} cb.session authenticated session
   */
  connectTree(session, shareName, shareLevelPassword, cb) {
    const share = this.shares[shareName]
    if (!share) {
      process.nextTick(function () {
        cb(new Error('share not found'))
      })
      return
    }
    const self = this
    share.connect(session, shareLevelPassword, function (err, tree) {
      if (err) {
        cb(err)
      } else {
        // register tree
        self.trees[tree.tid] = tree
        cb(null, tree)
        // emit event
        self.emit('shareConnected', shareName)
      }
    })
  }

  getTree(tid) {
    return this.trees[tid]
  }

  disconnectTree(tid) {
    const tree = this.trees[tid]
    if (tree) {
      const shareName = tree.getShare().getName()
      tree.disconnect()
      delete this.trees[tid]
      // emit event
      this.emit('shareDisconnected', shareName)
    }
  }

  /**
   * Clears the server's cache.
   * @param {function} cb Will be invoked when the operation is complete.
   * @param {string|Error} cb.err Will be truthy if there were errors during the operation.
   */
  clearCache(cb) {
    async.each(
      this.trees,
      function (t, callback) {
        t.clearCache(callback)
      },
      cb
    )
  }
}

SMBServer.connectionIdCounter = 0

export default SMBServer
