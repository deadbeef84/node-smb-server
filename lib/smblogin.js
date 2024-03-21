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

import * as utils from './utils.js'

const ANONYMOUS_KEY = 0

/**
 * Represents a login attempt as initiated by <code>NEGOTIATE</code> and
 * successfully finished by <code>SESSION_SETUP_ANDX</code>
 */
class SMBLogin {
  constructor(smbServer, challenge) {
    this.smbServer = smbServer
    if (challenge) {
      this.challenge = challenge
      this.key = ++SMBLogin.keyCounter
    } else {
      // represents anonymous login
      this.challenge = utils.EMPTY_BUFFER
      this.key = ANONYMOUS_KEY
    }
  }

  isAnonymous() {
    return this.key === ANONYMOUS_KEY
  }
}

SMBLogin.keyCounter = 0

export default SMBLogin
