/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'

export function retrieveBasket () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = security.authenticatedUsers.from(req)
      if (user?.data?.id == null) {
        res.status(401).json({ status: 'error', message: 'Unauthorized' })
        return
      }

      const id = req.params.id
      const basket = await BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
      if (basket == null) {
        res.status(404).json({ status: 'error', message: 'Not found' })
        return
      }
      if (basket.UserId !== user.data.id) {
        res.status(403).json({ status: 'error', message: 'Forbidden' })
        return
      }

      if (((basket?.Products) != null) && basket.Products.length > 0) {
        for (let i = 0; i < basket.Products.length; i++) {
          basket.Products[i].name = req.__(basket.Products[i].name)
        }
      }

      res.json(utils.queryResultToJson(basket))
    } catch (error) {
      next(error)
    }
  }
}
