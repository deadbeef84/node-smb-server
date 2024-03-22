import fsp from 'node:fs/promises'
import ntstatus from '../ntstatus.js'
import consts from '../smb/constants.js'
import { treeConnectResponse } from '../smb2/cmd/tree_connect.js'
import { createResponse } from '../smb2/cmd/create.js'

export class IpcShare {
  async connect(session, shareLevelPassword) {
    return [null, { status: ntstatus.STATUS_NOT_SUPPORTED }]
    /*
    return [
      new IpcTree(this),
      treeConnectResponse({
        type: 2,
        flags: 0,
        access: 0x001f00a9,
      })
    ]
    */
  }
}

class IpcTree {
  files = {}
  fidCounter = 0

  constructor(share) {
    this.share = share
  }

  async ioctl(req) {
    return { status: ntstatus.STATUS_NOT_SUPPORTED }
  }

  async create(path, req) {
    const file = new IpcFile(path)
    file.fid = ++this.fidCounter
    this.files[file.fid] = file

    const fileId = Buffer.from(file.fid.toString(16).padStart(32, '0'), 'hex')

    return createResponse({
      oplockLevel: 0,
      flags: 0,
      createAction: 1,
      creationTime: 0,
      lastAccessTime: 0,
      lastWriteTime: 0,
      changeTime: 0,
      allocationSize: 0,
      endOfFile: 0,
      fileAttributes: 0x1 | 0x10,
      fileId,
    })
  }

  getFileById(fid) {
    return this.files[fid]
  }

  async disconnect() {}
}

class IpcFile {
  constructor(path) {
    this.path = path
  }

  async close() {}
}
