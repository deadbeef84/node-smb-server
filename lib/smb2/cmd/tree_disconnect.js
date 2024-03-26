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

import binary from 'binary'
import baseLogger from '../../logger.js'

import ntstatus from '../../ntstatus.js'
const logger = baseLogger.child({ module: 'smb' })

export default async function handle(msg, related, connection, server) {
  if (msg.body.length < 4) {
    throw new Error('Invalid TREE_DISCONNECT packet header')
  }

  const req = binary.parse(msg.body).word16lu('structureSize').vars

  logger.debug(req, 'TREE_DISCONNECT')
  msg.tree.disconnect()
  connection.trees[msg.tree.tid] = null

  const res = put()
    .word16le(4) // StructureSize
    .word16le(0) // Reserved
    .buffer()

  msg.header.treeId = 0x60d1e5f1
  // msg.header.flags.priorityMask = true

  return {
    status: ntstatus.STATUS_SUCCESS,
    body: res,
  }
}
