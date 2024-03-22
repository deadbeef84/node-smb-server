import fsp from 'node:fs/promises'
import ntstatus from '../ntstatus.js'
import SMB2 from '../smb2/constants.js'
import consts from '../smb/constants.js'
import { treeConnectResponse } from '../smb2/cmd/tree_connect.js'
import { createResponse } from '../smb2/cmd/create.js'
import put from 'put'
import { systemToSMBTime } from '../utils.js'

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

    const fileId = Buffer.from(file.fid.toString(16).padStart(32, '0'), 'hex')
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
    fid = parseInt(fid.toString('hex'), 16)
    return this.files[fid]
  }

  async disconnect() {}
}

class NxtFile {
  constructor(path) {
    this.path = path
    this.query = 0
  }

  async queryDirectory(fileName, req) {
    if (req.flags & 0x1) {
      // reopen...
      this.query = 0
    }

    if (fileName === '*' && req.fileInformationClass === 0x25) {
      if (this.query) {
        return {
          status: ntstatus.STATUS_NO_MORE_FILES,
        }
      }

      this.query = 1

      // console.log('STAT', stat);

      const files = ['.', '..', ...(await fsp.readdir('.'))]

      let outputBuffer = Buffer.alloc(0)

      for (const file of files) {
        const name = Buffer.from(file, 'utf16le')
        const stat = await fsp.stat(file)
        const dir = stat.isDirectory()
        const buf = put()
          .word32le(0) // nextEntryOffset
          .word32le(0) // fileIndex
          .word64le(systemToSMBTime(stat.birthtimeMs)) // creationTime
          .word64le(systemToSMBTime(stat.atimeMs)) // lastAccessTime
          .word64le(systemToSMBTime(stat.mtimeMs)) // lastWriteTime
          .word64le(systemToSMBTime(stat.ctimeMs)) // changeTime
          .word64le(dir ? 0 : stat.size) // EndofFile
          .word64le(dir ? 0 : stat.blksize * stat.blocks) // AllocationSize
          .word32le(dir ? 0x1 | 0x10 : 0x1) // FileAttributes
          .word32le(name.length) // FileNameLength
          .word32le(0) // EaSize
          .word8(0) // shortNameLength
          .pad(1) // Reserved
          .pad(24) // ShortName
          .pad(2) // Reserved2
          .word64le(0) // FileId
          .put(name) // FileName
          .buffer()

        let pad = 0
        if (file !== files.at(-1)) {
          // not last...
          const paddedLength = Math.ceil(buf.length / 8) * 8
          buf.writeUInt32LE(paddedLength, 0)
          pad = paddedLength - buf.length
        }

        outputBuffer = Buffer.concat([outputBuffer, buf, Buffer.alloc(pad, 0)])
      }

      console.assert(outputBuffer.length <= req.outputBufferLength)

      const res = put()
        .word16le(9) // StructureSize
        .word16le(outputBuffer ? SMB2.HEADER_LENGTH + 8 : 0) // outputBufferOffset
        .word32le(outputBuffer.length) // outputBufferLength
        .put(outputBuffer)
        .buffer()

      return {
        status: ntstatus.STATUS_SUCCESS,
        body: res,
      }
    }

    return {
      status: ntstatus.STATUS_NOT_IMPLEMENTED,
    }
  }

  async close() {}
}
