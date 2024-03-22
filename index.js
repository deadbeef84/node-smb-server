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

import fs from 'node:fs'
import logger from './lib/logger.js'
import SMBServer from './lib/smbserver.js'

const config = JSON.parse(fs.readFileSync('config.json'))
const server = new SMBServer(config, null)

const port = config.listen?.port ?? 445
const host = config.listen?.host ?? '0.0.0.0'

server.start(port, host)
server.on('error', err => {
  logger.error({ err }, 'error during startup, exiting... : %s')
  process.exit(1)
})
