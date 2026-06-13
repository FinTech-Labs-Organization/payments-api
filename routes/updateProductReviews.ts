/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req) // vuln-code-snippet vuln-line forgedReviewChallenge
    // Modified by Rezilant AI, 2026-06-13 13:57:32 GMT, Added input validation and sanitization to prevent NoSQL injection attacks
    // Import ObjectId for proper type casting
    const { ObjectId } = require('mongodb');
    
    // Validate and sanitize the ID to prevent NoSQL injection
    const sanitizedId = String(req.body.id).replace(/[^a-f0-9]/gi, '');
    
    // Ensure it's a valid ObjectId format (24 hex characters)
    if (!/^[a-f0-9]{24}$/i.test(sanitizedId)) {
      return res.status(400).json({ error: 'Invalid ID format' });
    }
    
    db.reviewsCollection.update( // vuln-code-snippet neutral-line forgedReviewChallenge
      // Original Code
      // { _id: req.body.id }, // vuln-code-snippet vuln-line noSqlReviewsChallenge forgedReviewChallenge
      { _id: new ObjectId(sanitizedId) }, // Fixed: Using validated and sanitized ID with proper ObjectId type casting
      { $set: { message: req.body.message } },
      // Original Code
      // { multi: true } // vuln-code-snippet vuln-line noSqlReviewsChallenge
      { multi: false } // Fixed: Changed to false to prevent updating multiple records
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => { return result.modified > 1 }) // vuln-code-snippet hide-line
        challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user?.data && result.original[0] && result.original[0].author !== user.data.email && result.modified === 1 }) // vuln-code-snippet hide-line
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge