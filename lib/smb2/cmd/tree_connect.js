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

import put from 'put'
import assert from 'node:assert'

import binary from 'binary'
import baseLogger from '../../logger.js'

import ntstatus from '../../ntstatus.js'
const logger = baseLogger.child({ module: 'smb' })

export default async function handle(msg, related, connection, server) {
  if (msg.body.length < 9) {
    throw new Error('Invalid TREE_CONNECT packet header')
  }

  const req = binary
    .parse(msg.body)
    .word16lu('structureSize')
    .skip(2) // SMB3 flags, reserved otherwise
    .word16lu('pathOffset')
    .word16lu('pathLength').vars

  const path = msg.buf.subarray(req.pathOffset, req.pathOffset + req.pathLength).toString('utf16le')
  const m = path.match(/^\\\\([^\\]+)\\([^\\]+)$/)
  console.assert(m, 'invalid path')

  let [, serverName, shareName] = m
  logger.debug({...req, path, serverName, shareName }, 'TREE_CONNECT')

  shareName = shareName.toUpperCase()

  const [tree, response] = await server.connectTree(msg.session, shareName)
  if (tree) {
    assert(tree.tid, 'missing tree tid')
    assert(response, 'missing response')

    connection.trees[tree.tid] = tree
    msg.header.treeId = tree.tid
  }

  return response
}

export function treeConnectResponse({ status = ntstatus.STATUS_SUCCESS, type, flags, access }) {
  const res = put()
    .word16le(16) // StructureSize
    .word8(type) // ShareType
    .word8(0) // Reserved
    .word32le(flags) // ShareFlags
    .word32le(0) // Capabilities
    .word32le(access) // MaximalAccess
    .buffer()

  return { status, body: res }
}
