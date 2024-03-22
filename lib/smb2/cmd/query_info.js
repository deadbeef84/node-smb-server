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

import binary from 'binary'

export default async function handle(msg, related, connection, server) {
  if (msg.body.length < 9) {
    throw new Error('Invalid QUERY_INFO packet header')
  }

  const req = binary
    .parse(msg.body)
    .word16le('structureSize')
    .word8('infoType')
    .word8('fileInfoClass')
    .word32le('outputBufferLength')
    .word16le('inputBufferOffset')
    .skip(2) // reserved
    .word32le('inputBufferLength')
    .word32le('additionalInformation')
    .word32le('flags')
    .buffer('fileId', 16).vars

  console.log('QUERY_INFO', req)

  return msg.tree.getFileById(req.fileId).queryInfo(req)
}
