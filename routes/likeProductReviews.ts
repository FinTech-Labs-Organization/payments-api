/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { type Review } from '../data/types'
import * as db from '../data/mongodb'
import { ObjectId } from 'mongodb'

const sleep = async (ms: number) => await new Promise(resolve => setTimeout(resolve, ms))

export function likeProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const id = req.body.id
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    try {
      // Modified by Rezilant AI, 2026-06-13 14:19:23 GMT, Added validation and sanitization to prevent NoSQL injection attacks
      // Validate that id is a valid ObjectId format to prevent NoSQL injection
      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ error: 'Invalid ID format' })
      }

      // Create a new ObjectId instance to sanitize the input
      const sanitizedId = new ObjectId(id)

      // Original Code
      // const review = await db.reviewsCollection.findOne({ _id: id })
      const review = await db.reviewsCollection.findOne({ _id: sanitizedId })
      if (!review) {
        return res.status(404).json({ error: 'Not found' })
      }

      const likedBy = review.likedBy
      if (likedBy.includes(user.data.email)) {
        return res.status(403).json({ error: 'Not allowed' })
      }

      // Modified by Rezilant AI, 2026-06-13 14:19:23 GMT, Use sanitized ID to prevent NoSQL injection
      // Original Code
      // await db.reviewsCollection.update(
      //   { _id: id },
      //   { $inc: { likesCount: 1 } }
      // )
      await db.reviewsCollection.update(
        { _id: sanitizedId },
        { $inc: { likesCount: 1 } }
      )

      // Artificial wait for timing attack challenge
      await sleep(150)
      try {
        // Modified by Rezilant AI, 2026-06-13 14:19:23 GMT, Use sanitized ID to prevent NoSQL injection
        // Original Code
        // const updatedReview: Review = await db.reviewsCollection.findOne({ _id: id })
        const updatedReview: Review = await db.reviewsCollection.findOne({ _id: sanitizedId })
        const updatedLikedBy = updatedReview.likedBy
        updatedLikedBy.push(user.data.email)

        const count = updatedLikedBy.filter(email => email === user.data.email).length
        challengeUtils.solveIf(challenges.timingAttackChallenge, () => count > 2)

        // Modified by Rezilant AI, 2026-06-13 14:19:23 GMT, Use sanitized ID to prevent NoSQL injection
        // Original Code
        // const result = await db.reviewsCollection.update(
        //   { _id: id },
        //   { $set: { likedBy: updatedLikedBy } }
        // )
        const result = await db.reviewsCollection.update(
          { _id: sanitizedId },
          { $set: { likedBy: updatedLikedBy } }
        )
        res.json(result)
      } catch (err) {
        res.status(500).json(err)
      }
    } catch (err) {
      res.status(400).json({ error: 'Wrong Params' })
    }
  }
}