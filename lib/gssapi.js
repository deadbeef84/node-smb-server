import { Asn1Obj } from './asn1.js'
import ntstatus from './ntstatus.js'
import * as ntlm from './ntlm.js'
import * as ntlmssp from './ntlmssp.js'
import { default as NTLMSSP } from './ntlmssp.js'
import asn1js from 'asn1js'
import crypto from 'node:crypto'

const spnegoTokenInitBytes = [
  0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x3e, 0x30, 0x3c, 0xa0, 0x0e,
  0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa3, 0x2a,
  0x30, 0x28, 0xa0, 0x26, 0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x65,
  0x64, 0x5f, 0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31, 0x37, 0x38, 0x40, 0x70, 0x6c, 0x65,
  0x61, 0x73, 0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65,
]

const flags = [
  'NTLMSSP_NEGOTIATE_UNICODE',
  'NTLMSSP_NEGOTIATE_OEM',
  'NTLMSSP_REQUEST_TARGET',
  'NTLMSSP_RESERVED_10',
  'NTLMSSP_NEGOTIATE_SIGN',
  'NTLMSSP_NEGOTIATE_SEAL',
  'NTLMSSP_NEGOTIATE_DATAGRAM',
  'NTLMSSP_NEGOTIATE_LM_KEY',
  'NTLMSSP_RESERVED_9',
  'NTLMSSP_NEGOTIATE_NTLM',
  'NTLMSSP_RESERVED_8',
  'NTLMSSP_NEGOTIATE_ANONYMOUS',
  'NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED',
  'NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED',
  'NTLMSSP_RESERVED_7',
  'NTLMSSP_NEGOTIATE_ALWAYS_SIGN',
  'NTLMSSP_TARGET_TYPE_DOMAIN',
  'NTLMSSP_TARGET_TYPE_SERVER',
  'NTLMSSP_RESERVED_6',
  'NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY',
  'NTLMSSP_NEGOTIATE_IDENTIFY',
  'NTLMSSP_RESERVED_5',
  'NTLMSSP_REQUEST_NON_NT_SESSION_KEY',
  'NTLMSSP_NEGOTIATE_TARGET_INFO',
  'NTLMSSP_RESERVED_4',
  'NTLMSSP_NEGOTIATE_VERSION',
  'NTLMSSP_RESERVED_3',
  'NTLMSSP_RESERVED_2',
  'NTLMSSP_RESERVED_1',
  'NTLMSSP_NEGOTIATE_128',
  'NTLMSSP_NEGOTIATE_KEY_EXCH',
  'NTLMSSP_NEGOTIATE_56',
]

const SPNEGO = '1.3.6.1.5.5.2'
const NTLM = '1.3.6.1.4.1.311.2.2.10'

const ApplicationTag = 0x60

const NegTokenInitTag = 0xa0
const MechanismTypeListTag = 0xa0
const RequiredFlagsTag = 0xa1
const MechanismTokenTag = 0xa2
const MechanismListMICTag = 0xa3

const NegTokenRespTag = 0xa1
const NegStateTag = 0xa0
const SupportedMechanismTag = 0xa1
const ResponseTokenTag = 0xa2
// let MechanismListMICTag = 0xA3

export function GetSPNEGOTokenInitBytes() {
  return Buffer.from(spnegoTokenInitBytes)
}

export function AcceptSecurityContext(context, inputToken) {
  const root = Asn1Obj.load(inputToken)

  let token

  // Generic GSSAPI header
  if (root.getTag() === ApplicationTag) {
    const thisMech = root.getChild(0).getValueAsObjectIdentifier()
    if (thisMech !== SPNEGO) {
      throw new Error('Expected SPNEGO object-identifier')
    }

    const negotiationToken = root.getChild(1)
    if (negotiationToken.getTag() !== NegTokenInitTag) {
      throw new Error('Invalid negotiation token tag, expected NegTokenInit')
    }

    const out = {}
    const negTokenInit = negotiationToken.getChild(0)
    for (const el of negTokenInit.getChildren()) {
      if (el.getTag() === MechanismTypeListTag) {
        out.mechTypes = el
          .getChild(0)
          .getChildren()
          .map((oid) => oid.getValueAsObjectIdentifier())
      } else if (el.getTag() === MechanismTokenTag) {
        out.mechToken = el.getChild(0).getValue()
      } else {
        // throw new Error('Unsupported tag')
      }
    }

    console.log('negTokenInit', out)

    if (!out.mechTypes.includes(NTLM)) {
      throw new Error('Expected NTLM in mechTypes')
    }

    token = out.mechToken
  } else if (root.getTag() === NegTokenRespTag) {
    const negTokenResp = root.getChild(0)
    const out = {}
    for (const el of negTokenResp.getChildren()) {
      if (el.getTag() === ResponseTokenTag) {
        out.responseToken = el.getChild(0).getValue()
      } else if (el.getTag() === MechanismListMICTag) {
        out.mechListMIC = el.getChild(0).getValue()
      } else {
        // throw new Error('Unsupported tag')
      }
    }
    console.log('negTokenResp', out)
    token = out.responseToken
  } else {
    throw new Error('Unknown token 0x' + root.getTag().toString(16))
  }

  if (!token) {
    throw new Error('Unable to parse token')
  }

  const msgType = ntlmssp.parseMessageType(token)
  if (msgType === NTLMSSP.NTLMSSP_NEGOTIATE_MESSAGE) {
    return negotiate(context, token)
  } else if (msgType === NTLMSSP.NTLMSSP_AUTHENTICATE_MESSAGE) {
    return authenticate(context, token)
  } else {
    throw new Error('Unknown ntlmssp message type')
  }
}

function negotiate(context, token) {
  const negMsg = ntlmssp.parseNegotiateMessage(token)

  console.log('ntlmssp negotiate', negMsg)

  if (!negMsg) {
    throw new Error('Unable to parse ntlmssp negotiate message')
  }

  for (const flag of flags) {
    console.log(negMsg.flags2 & NTLMSSP[flag] ? '*' : ' ', flag, NTLMSSP[flag].toString(2))
  }

  // create NTLMSSP_CHALLENGE msg
  const challenge = ntlm.createChallenge()
  context.challenge = challenge
  const responseToken = ntlmssp.createChallengeMessage(
    // negMsg.flags,
    0x628a8215,
    challenge,
    context.hostName,
    context.domainName
  )

  const negTokenResp = new asn1js.Constructed({
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

  return [ntstatus.STATUS_MORE_PROCESSING_REQUIRED, Buffer.from(negTokenResp.toBER())]
}
function authenticate(context, token) {
  const authMsg = ntlmssp.parseAuthenticateMessage(token)
  console.log('ntlmssp authenticate', authMsg, context)

  if (!authMsg) {
    throw new Error('parsing authenticate message failed')
  }

  const password = 'bar'
  const ntlmHash = ntlm.ntlm.createHash(password)

  const authenticated = ntlm.validateNTLMv2Response(
    authMsg.ntResponse,
    ntlmHash,
    authMsg.user,
    authMsg.domain,
    context.challenge
  )

  const responseKeyNT = NTOWFv2(password, authMsg.user, authMsg.domain)
  const ntProofStr = authMsg.ntResponse.slice(0, 16)
  const sessionBaseKey = HMAC_MD5(responseKeyNT, ntProofStr)
  const keyExchangeKey = sessionBaseKey

  const sessionKey = RC4_DECRYPT(keyExchangeKey, authMsg.sessionKey)

  console.log('authentication success', {
    responseKeyNT,
    ntProofStr,
    sessionBaseKey,
    keyExchangeKey,
    sessionKey,
  })

  context.sessionKey = sessionKey

  const negTokenResp = new asn1js.Constructed({
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
  })
  return [ntstatus.STATUS_SUCCESS, Buffer.from(negTokenResp.toBER())]
}

function getUnicodeBytes(text) {
  return Buffer.from(text, 'utf16le')
}

function MD4(data) {
  return crypto.createHash('md4').update(data).digest()
}

function HMAC_MD5(key, data) {
  return crypto.createHmac('md5', key).update(data).digest()
}

function NTOWFv2(password, user, domain) {
  const passwordBytes = getUnicodeBytes(password)
  const key = MD4(passwordBytes)
  const text = user.toUpperCase() + domain
  const bytes = getUnicodeBytes(text)
  return HMAC_MD5(key, bytes)
}

function RC4_DECRYPT(key, data, encodingIn = 'binary', encodingOut = 'binary') {
  const decipher = crypto.createDecipheriv('rc4', key, '')
  const decrypted = decipher.update(data, encodingIn)
  return Buffer.concat([decrypted, decipher.final()])
}
