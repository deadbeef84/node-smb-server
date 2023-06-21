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

'use strict';

var put = require('put');
var binary = require('binary');
var logger = require('winston').loggers.get('smb');

var ntstatus = require('../../ntstatus');
var ntlm = require('../../ntlm');
var ntlmssp = require('../../ntlmssp');
var SMB2 = require('../constants');
var utils = require('../../utils');

var { Asn1Obj } = require('../../asn1');
var asn1js = require('asn1js');

/**
 * SMB2_NEGOTIATE (0x0000): Negotiate protocol dialect.
 *
 * @param {Object} msg - an SMB message object
 * @param {Number} commandId - the command id
 * @param {Buffer} body - the command specific message body
 * @param {Object} related - context for related operations (null for unrelated operation)
 * @param {Long} related.sessionId - sessionId
 * @param {Number} related.treeId - treeId
 * @param {Object} related.fileId - fileId
 * @param {Object} connection - an SMBConnection instance
 * @param {Object} server - an SMBServer instance
 * @param {Function} cb callback called with the command's result
 * @param {Object} cb.result - an object with the command's result
 *                             or null if the handler already sent the response and
 *                             no further processing is required by the caller
 * @param {Number} cb.result.status
 * @param {Buffer} cb.result.body
 */
function handle(msg, commandId, body, related, connection, server, cb) {
  if (body.length < 64) {
    throw new Error('Invalid SESSION_SETUP packet header');
  }

  const req = binary
    .parse(body)
    .word16lu('structureSize')
    .word8('flags')
    .word8('securityMode')
    .word32lu('capabilities')
    .word32lu('channel')
    .word16lu('securityBufferOffset')
    .word16lu('securityBufferLength')
    .word64lu('previousSessionId').vars;

  console.log('SESSION_SETUP', req);

  // process.nextTick(function () {
  //   cb({
  //     status: ntstatus.STATUS_NOT_SUPPORTED,
  //     body: utils.EMPTY_BUFFER
  //   });
  // });
  // return

  let status = ntstatus.STATUS_SUCCESS;

  const sb = msg.buf.slice(req.securityBufferOffset);

  var asn1Obj = Asn1Obj.load(Buffer.from(sb));
  recurse(asn1Obj);
  var spnego = asn1Obj.getChild(0)?.getValueAsObjectIdentifier();
  var mechTypes = asn1Obj
    ?.getChild(1) // NegotiationToken
    ?.getChild(0) // NegTokenInit (sequence)
    ?.getChild(0) // mechTypes (MechTypeList)
    ?.getChild(0) // MechTypeList (sequence)
    ?.getChildren()
    .map((oid) => oid.getValueAsObjectIdentifier());

  var token = asn1Obj
    .getChild(1) // NegotiationToken
    ?.getChild(0) // NegTokenInit (sequence)
    ?.getChild(1) // mechToken (octet string)
    ?.getChild(0)
    ?.getValue();

  if (!token) {
    token = asn1Obj
      ?.getChild(0) // NegTokenInit (sequence)
      ?.getChild(0) // mechToken (octet string)
      ?.getChild(0)
      ?.getValue();
  }

  console.log('SPNEGO = ' + (spnego === '1.3.6.1.5.5.2' ? 'Y' : 'N'));
  console.log('mechTypes=', mechTypes); // NTLM=1.3.6.1.4.1.311.2.2.10
  console.log('token=', token.toString('ascii'));

  if (!token) {
    console.log('not supported');
    process.nextTick(function () {
      cb({
        status: ntstatus.STATUS_NOT_SUPPORTED,
        body: put()
          .word16le(0x0009) // StructureSize (fixed according to spec)
          .word8(0) // ErrorContextCount
          .pad(1) // Reserved
          .word32le(0) // ByteCount
          .word8(0) // ErrorData
          .buffer(),
      });
    });
    return;
  }

  // console.log(Buffer.from(asn1Obj.createArrayBuffer()).toString("hex"));

  // var negTokenResp = new asn1js.Constructed({
  //   idBlock: {
  //     tagClass: 2, // application,
  //     tagNumber: 0
  //   },
  //   value: [
  //     new asn1js.ObjectIdentifier({
  //       value: "1.3.6.1.5.5.2"
  //     }),
  //     new asn1js.Constructed({
  //       idBlock: {
  //         tagClass: 3,
  //         tagNumber: 0
  //       },
  //       value: [
  //         new asn1js.Sequence({
  //           value: [
  //             new asn1js.Constructed({
  //               idBlock: {
  //                 tagClass: 3,
  //                 tagNumber: 0
  //               },
  //               value: [
  //                 new asn1js.Sequence({
  //                   name: "mechTypes",
  //                   value: [
  //                     new asn1js.ObjectIdentifier({
  //                       value: '1.3.6.1.4.1.311.2.2.10'
  //                     })
  //                   ]
  //                 }),
  //               ]
  //             }),
  //             new asn1js.Constructed({
  //               idBlock: {
  //                 tagClass: 3,
  //                 tagNumber: 2
  //               },
  //               value: [
  //                 new asn1js.OctetString({
  //                   name: "mechToken",
  //                   valueHex: token,
  //                   optional: true
  //                 }),
  //               ]
  //             }),
  //           ]
  //         })
  //       ]
  //     })
  //   ]
  // });
  // const res = Buffer.from(negTokenResp.toBER())
  // console.log(res.toString('hex'))
  // recurse(Asn1Obj.load(res))

  let responseToken;
  var msgType = ntlmssp.parseMessageType(token);
  let authMsg;

  if (msgType === ntlmssp.NTLMSSP_NEGOTIATE_MESSAGE) {
    // parse NTLMSSP_NEGOTIATE msg
    var negMsg = ntlmssp.parseNegotiateMessage(token);
    if (!negMsg) {
      // cb(buildResult(ntstatus.STATUS_LOGON_FAILURE, 0, extendedSecurity, securityBlob));
      return;
    }

    // create NTLMSSP_CHALLENGE msg
    const challenge = ntlm.createChallenge();
    responseToken = ntlmssp.createChallengeMessage(
      negMsg.flags,
      challenge,
      server.hostName,
      server.domainName
    );

    msg.header.sessionId = 12345678; // TODO: bigint...

    status = ntstatus.STATUS_MORE_PROCESSING_REQUIRED;
  } else if (msgType === ntlmssp.NTLMSSP_AUTHENTICATE_MESSAGE) {
    // parse NTLMSSP_AUTHENTICATE msg
    authMsg = ntlmssp.parseAuthenticateMessage(token);
    if (!authMsg) {
      // cb(buildResult(ntstatus.STATUS_LOGON_FAILURE, 0, extendedSecurity, securityBlob));
      return;
    }
    // msg.accountName = authMsg.user;
    // msg.primaryDomain = authMsg.domain;
    // msg.caseInsensitivePassword = authMsg.lmResponse;
    // msg.caseSensitivePassword = authMsg.ntResponse;

    console.log('authenticated!', authMsg);
  } else {
    // error
    logger.debug(
      '[%s] illegal NTLMSSP message type %d',
      SMB.COMMAND_TO_STRING[commandId].toUpperCase(),
      msgType
    );
    // cb(buildResult(ntstatus.STATUS_LOGON_FAILURE, 0, extendedSecurity, securityBlob));
    return;
  }

  var negTokenResp = responseToken
    ? new asn1js.Constructed({
        idBlock: {
          tagClass: 3,
          tagNumber: 1, // NegTokenResp
        },
        value: [
          new asn1js.Sequence({
            value: [
              new asn1js.Constructed({
                idBlock: {
                  tagClass: 3,
                  tagNumber: 0, // negState
                },
                value: [
                  new asn1js.Enumerated({
                    value: 1, // accept-incomplete
                  }),
                ],
              }),
              new asn1js.Constructed({
                idBlock: {
                  tagClass: 3,
                  tagNumber: 1, // supportedMech
                },
                value: [
                  new asn1js.ObjectIdentifier({
                    value: '1.3.6.1.4.1.311.2.2.10',
                  }),
                ],
              }),
              new asn1js.Constructed({
                idBlock: {
                  tagClass: 3,
                  tagNumber: 2, // responseToken
                },
                value: [
                  new asn1js.OctetString({
                    valueHex: responseToken,
                  }),
                ],
              }),
            ],
          }),
        ],
      })
    : new asn1js.Constructed({
        idBlock: {
          tagClass: 3,
          tagNumber: 1, // NegTokenResp
        },
        value: [
          new asn1js.Sequence({
            value: [
              new asn1js.Constructed({
                idBlock: {
                  tagClass: 3,
                  tagNumber: 0, // negState
                },
                value: [
                  new asn1js.Enumerated({
                    value: 0, // accept-complete
                  }),
                ],
              }),
              // new asn1js.Constructed({
              //   idBlock: {
              //     tagClass: 3,
              //     tagNumber: 3, // mechListMIC
              //   },
              //   value: [
              //     new asn1js.OctetString({
              //       valueHex: authMsg.mic,
              //     }),
              //   ],
              // }),
            ],
          }),
        ],
      });

  const securityBuffer = Buffer.from(negTokenResp.toBER());

  const res = put()
    .word16le(9) // StructureSize
    .word16le(0) // SessionFlags
    .word16le(SMB2.HEADER_LENGTH + 8) // SecurityBufferOffset
    .word16le(securityBuffer.length) // SecurityBufferLength
    .put(securityBuffer) // SecurityBuffer
    .buffer();

  // return result
  const result = {
    status,
    body: res,
  };
  process.nextTick(function () {
    cb(result);
  });
}

function recurse(o, depth = 0) {
  const tag = o.getTag();
  const constructed = tag & 0b100000;
  const type =
    {
      0: 'Universal',
      1: 'App',
      2: 'Context',
      3: 'Private',
    }[tag >> 6] ?? '?';
  console.log(
    `${' '.repeat(depth * 2)}${type}-${constructed ? 'c' : 'p'}-${
      tag & 0b11111
    }: ${o.getValueAsObjectIdentifier() ?? o.getValue()}`
  );
  for (const c of o.getChildren()) {
    recurse(c, depth + 1);
  }
}

module.exports = handle;
