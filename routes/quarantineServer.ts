/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveQuarantineFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Modified by Rezilant AI, 2026-06-13 14:04:25 GMT, Added path canonicalization and directory boundary checks to prevent path traversal attacks
    // Define the allowed base directory
    const baseDir = path.resolve('ftp/quarantine/')
    
    // Resolve the full path
    const fullPath = path.resolve(baseDir, file)
    
    // Check if the resolved path is within the allowed directory
    if (!fullPath.startsWith(baseDir + path.sep)) {
      res.status(403)
      return next(new Error('Access denied: Invalid file path'))
    }
    
    // Additional validation: only allow alphanumeric characters, dots, dashes, and underscores
    if (!/^[\w.-]+$/.test(file)) {
      res.status(403)
      return next(new Error('Access denied: Invalid filename format'))
    }

    res.sendFile(fullPath)
    
    // Original Code
    // if (!file.includes('/')) {
    //   res.sendFile(path.resolve('ftp/quarantine/', file))
    // } else {
    //   res.status(403)
    //   next(new Error('File names cannot contain forward slashes!'))
    // }
  }
}