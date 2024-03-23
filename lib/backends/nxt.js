import fsp from 'node:fs/promises'
import ntstatus from '../ntstatus.js'
import SMB2 from '../smb2/constants.js'
import consts from '../smb/constants.js'
import { treeConnectResponse } from '../smb2/cmd/tree_connect.js'
import { createResponse } from '../smb2/cmd/create.js'
import put from 'put'
import { systemToSMBTime } from '../utils.js'
import { Flags } from '../smb2/cmd/query_directory.js'
import { FileAttributes, FileInformationClass, FileSystemInformationClass } from '../enum.js'
import { InfoType } from '../smb2/cmd/query_info.js'

export class NxtShare {
  async connect(session, shareLevelPassword) {
    return [
      new NxtTree(this),
      treeConnectResponse({
        type: 1,
        flags: 0x00000010 | 0x00000020 | 0x00000100 | 0x00000200,
        access: consts.FILE_READ_ATTRIBUTES | consts.FILE_LIST_DIRECTORY,
      }),
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
    const file = new NxtFile(path || '.')
    file.fid = ++this.fidCounter
    this.files[file.fid] = file

    const fileId = Buffer.from(file.fid.toString(16).padStart(32, '0'), 'hex')
    const stat = await fsp.stat(path || '.')
    const dir = stat.isDirectory()

    return createResponse({
      oplockLevel: 0,
      flags: 0,
      createAction: 0x1, // OPENED
      creationTime: stat.birthtime,
      lastAccessTime: stat.atime,
      lastWriteTime: stat.mtime,
      changeTime: stat.ctime,
      allocationSize: dir ? 0 : stat.blksize * stat.blocks,
      endOfFile: dir ? 0 : stat.size,
      fileAttributes: FileAttributes.ReadOnly | (dir ? FileAttributes.Directory : 0),
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
    this.handle = null
  }

  async read(req) {
    const { length, offset, minimumCount } = req
    this.handle ??= await fsp.open(this.path, 'r')
    const buffer = Buffer.allocUnsafe(length)
    const { bytesRead } = await this.handle.read({ buffer, length, position: offset })
    console.log({ bytesRead, buffer })
    // TODO: STATUS_END_OF_FILE
    const body = put()
      .word16le(17) // StructureSize
      .word8(SMB2.HEADER_LENGTH + 16) // DataOffset
      .pad(1)
      .word32le(bytesRead) // DataLength
      .word32le(0) // DataRemaining - TODO?
      .pad(4)
      .put(buffer)
      .buffer()
    return {
      status: ntstatus.STATUS_SUCCESS,
      body,
    }
  }

  async queryDirectory(fileName, req) {
    if (req.flags & Flags.SMB2_RESTART_SCANS) {
      // reopen...
      this.query = 0
    }

    if (
      fileName === '*' &&
      req.fileInformationClass === FileInformationClass.FileIdBothDirectoryInformation
    ) {
      if (this.query) {
        return { status: ntstatus.STATUS_NO_MORE_FILES }
      }

      this.query = 1

      // console.log('STAT', stat);

      const files = ['.', '..', ...(await fsp.readdir(this.path))]

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
          .word32le(FileAttributes.ReadOnly | (dir ? FileAttributes.Directory : 0)) // FileAttributes
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

  async queryInfo(req) {
    if (
      req.infoType === InfoType.SMB2_0_INFO_FILESYSTEM &&
      req.fileInfoClass === FileSystemInformationClass.FileFsSizeInformation
    ) {
      const stat = await fsp.statfs(this.path)

      const outputBuffer = put()
        .word64le(stat.blocks) // total allocation units
        .word64le(stat.bavail) // available allocation units
        .word32le(stat.bsize / 512) // sectors per allocation unit
        .word32le(512) // bytes per sector
        .buffer()

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

    if (
      req.infoType === InfoType.SMB2_0_INFO_FILE &&
      req.fileInfoClass === FileInformationClass.FileNetworkOpenInformation
    ) {
      const stat = await fsp.stat(this.path)
      const dir = stat.isDirectory()

      const outputBuffer = put()
        .word64le(systemToSMBTime(stat.birthtimeMs)) // creationTime
        .word64le(systemToSMBTime(stat.atimeMs)) // lastAccessTime
        .word64le(systemToSMBTime(stat.mtimeMs)) // lastWriteTime
        .word64le(systemToSMBTime(stat.ctimeMs)) // changeTime
        .word64le(dir ? 0 : stat.blksize * stat.blocks) // AllocationSize
        .word64le(dir ? 0 : stat.size) // EndofFile
        .word32le(FileAttributes.ReadOnly | (dir ? FileAttributes.Directory : 0)) // FileAttributes
        .pad(4) // Reserved
        .buffer()

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

    if (
      req.infoType === InfoType.SMB2_0_INFO_FILE &&
      req.fileInfoClass === FileInformationClass.FileAllInformation
    ) {
      const stat = await fsp.stat(this.path)
      const dir = stat.isDirectory()

      const name = Buffer.from('nxt', 'utf16le')

      const outputBuffer = put()
        // FileBasicInformation
        .word64le(systemToSMBTime(stat.birthtimeMs)) // creationTime
        .word64le(systemToSMBTime(stat.atimeMs)) // lastAccessTime
        .word64le(systemToSMBTime(stat.mtimeMs)) // lastWriteTime
        .word64le(systemToSMBTime(stat.ctimeMs)) // changeTime
        .word32le(FileAttributes.ReadOnly | (dir ? FileAttributes.Directory : 0)) // FileAttributes
        .pad(4) // Reserved
        // FileStandardInformation
        .word64le(dir ? 0 : stat.blksize * stat.blocks) // AllocationSize
        .word64le(dir ? 0 : stat.size) // EndofFile
        .word32le(0) // NumberOfLinks
        .word8(0) // DeletePending
        .word8(dir ? 1 : 0) // Directory
        .pad(2) // Reserved
        // FileInternalInformation
        .word64le(0) // IndexNumber (TODO: fileId?)
        // EaInformation
        .word32le(0) // EaSize
        // FileAccessInformation
        .word32le(0) // AccessFlags: TODO
        // FilePositionInformation
        .word64le(0) // CurrentByteOffset: TODO
        // ModeInformation
        .word32le(0) // Mode: TODO
        // AlignmentInformation
        .word32le(0) // AlignmentRequirement
        // NameInformation
        .word32le(name.length)
        .put(name)
        .buffer()

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
      status: ntstatus.STATUS_NOT_SUPPORTED,
    }
  }

  async close() {}
}
