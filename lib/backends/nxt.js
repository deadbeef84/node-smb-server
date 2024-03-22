import fsp from 'node:fs/promises'
import ntstatus from '../ntstatus.js'
import consts from '../smb/constants.js'
import { treeConnectResponse } from '../smb2/cmd/tree_connect.js'
import { createResponse } from '../smb2/cmd/create.js'

export class NxtShare {
  async connect(session, shareLevelPassword) {
    return [
      new NxtTree(this),
      treeConnectResponse({
        type: 1,
        flags: 0x00000010 | 0x00000020 | 0x00000100 | 0x00000200,
        access: consts.FILE_READ_ATTRIBUTES | consts.FILE_LIST_DIRECTORY,
      })
    ]
  }
}

class NxtTree {
  files = {}
  fidCounter = 0

  constructor(share) {
    this.share = share
  }

  async ioctl(req) {
    return { status: ntstatus.STATUS_NOT_SUPPORTED }
  }

  async create(path, req) {
    const file = new NxtFile(path)
    file.fid = ++this.fidCounter
    this.files[file.fid] = file

    const fileId = Buffer.from(file.fid.toString(16).padStart(16, '0'), 'hex')
    const stat = await fsp.stat(path || '.')

    return createResponse({
      oplockLevel: 0,
      flags: 0,
      createAction: 1,
      creationTime: stat.birthtime,
      lastAccessTime: stat.atime,
      lastWriteTime: stat.mtime,
      changeTime: stat.ctime,
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

class NxtFile {
  constructor(path) {
    this.path = path
  }

  async close() {}
}
