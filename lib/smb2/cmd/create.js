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
import ntstatus from '../../ntstatus.js'
import * as utils from '../../utils.js'
import { AccessMask, CreateDisposition, CreateOptions, DirectoryAccessMask, FileAccessMask, FileAttributes, ImpersonationLevel, ShareAccess } from '../../enum.js'

export default async function handle(msg, related, connection, server) {
  if (msg.body.length < 9) {
    throw new Error('Invalid TREE_CONNECT packet header')
  }

  const req = binary
    .parse(msg.body)
    .word16lu('structureSize')
    .skip(1) // reserved
    .word8('reqOplockLevel')
    .word32le('impersonationLevel')
    .word64le('createFlags') // ignore
    .skip(8)
    .word32le('desiredAccess')
    .word32le('fileAttributes')
    .word32le('shareAccess')
    .word32le('createDisposition')
    .word32le('createOptions')
    .word16le('nameOffset')
    .word16le('nameLength')
    .word32le('createContextOffset')
    .word32le('createContextLength').vars

  const name = msg.buf.subarray(req.nameOffset, req.nameOffset + req.nameLength).toString('utf16le')

  console.log('CREATE', msg.tree.share, name, {
    ...req,
    impersonationLevel: utils.enumToStr(req.impersonationLevel, ImpersonationLevel),
    desiredAccess: utils.enumToStr(req.fileAttributes, DirectoryAccessMask),
    fileAttributes: utils.enumToStr(req.fileAttributes, FileAttributes),
    shareAccess: utils.enumToStr(req.shareAccess, ShareAccess),
    createDisposition: utils.enumToStr(req.createDisposition, CreateDisposition),
    createOptions: utils.enumToStr(req.createDisposition, CreateOptions),
  })

  return await msg.tree.create(name, req)
}

export function createResponse(x) {
  const {
    status = ntstatus.STATUS_SUCCESS,
    oplockLevel,
    flags,
    createAction,
    creationTime,
    lastAccessTime,
    lastWriteTime,
    changeTime,
    allocationSize,
    endOfFile,
    fileAttributes,
    fileId,
  } = x
  console.log('CREATE RESPONSE', x)

  const body = put()
    .word16le(89) // StructureSize
    .word8(oplockLevel)
    .word8(flags)
    .word32le(createAction)
    .word64le(utils.systemToSMBTime(creationTime))
    .word64le(utils.systemToSMBTime(lastAccessTime))
    .word64le(utils.systemToSMBTime(lastWriteTime))
    .word64le(utils.systemToSMBTime(changeTime))
    .word64le(allocationSize)
    .word64le(endOfFile)
    .word32le(fileAttributes)
    .pad(4) // Reserved2
    .put(fileId) // 16 bytes, fileId
    .word32le(0) // CreateContextsOffset
    .word32le(0) // CreateContextLength
    .buffer()
  return { status, body }
}
