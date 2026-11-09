/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { retrieveBasket } from '../../routes/basket'
import { BasketModel } from '../../models/basket'
import { authenticatedUsers } from '../../lib/insecurity'

void describe('basket authorization', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    mock.restoreAll()
    req = { params: { id: '101' }, __: mock.fn((s) => 'localized:' + s) }
    res = { status: mock.fn(() => res), json: mock.fn() }
    next = mock.fn()
  })

  afterEach(() => {
    mock.restoreAll()
  })

  for (const user of [{ id: 7, basketId: 101 }, { id: 9, basketId: 202 }]) {
    void it('allows owner ' + user.id + ' to read and localize their basket', async () => {
      const basket = { id: user.basketId, UserId: user.id, Products: [{ name: 'Juice' }] }
      req.params.id = String(user.basketId)
      mock.method(authenticatedUsers, 'from', () => ({ data: { id: user.id }, bid: user.basketId }))
      mock.method(BasketModel, 'findOne', async () => basket)

      await retrieveBasket()(req, res, next)

      assert.equal(res.status.mock.calls.length, 0)
      assert.equal(res.json.mock.calls.length, 1)
      assert.deepEqual(res.json.mock.calls[0].arguments[0], { status: 'success', data: basket })
      assert.equal(basket.Products[0].name, 'localized:Juice')
      assert.equal(next.mock.calls.length, 0)
    })
  }

  for (const pair of [{ userId: 7, basketId: 202, ownerId: 9 }, { userId: 9, basketId: 101, ownerId: 7 }]) {
    void it('denies cross-user access from ' + pair.userId + ' to owner ' + pair.ownerId, async () => {
      const basket = { id: pair.basketId, UserId: pair.ownerId, Products: [{ name: 'Private product' }] }
      req.params.id = String(pair.basketId)
      mock.method(authenticatedUsers, 'from', () => ({ data: { id: pair.userId } }))
      mock.method(BasketModel, 'findOne', async () => basket)

      await retrieveBasket()(req, res, next)

      assert.equal(res.status.mock.calls[0].arguments[0], 403)
      assert.deepEqual(res.json.mock.calls[0].arguments[0], { status: 'error', message: 'Forbidden' })
      assert.equal(req.__.mock.calls.length, 0)
      assert.equal(basket.Products[0].name, 'Private product')
      assert.equal(next.mock.calls.length, 0)
    })
  }

  for (const identity of [
    { name: 'missing authentication context', value: undefined },
    { name: 'missing user data', value: {} },
    { name: 'missing user ID', value: { data: {} } }
  ]) {
    void it('returns 401 before querying a basket for ' + identity.name, async () => {
      mock.method(authenticatedUsers, 'from', () => identity.value)
      const query = mock.method(BasketModel, 'findOne', async () => null)

      await retrieveBasket()(req, res, next)

      assert.equal(res.status.mock.calls[0].arguments[0], 401)
      assert.deepEqual(res.json.mock.calls[0].arguments[0], { status: 'error', message: 'Unauthorized' })
      assert.equal(query.mock.calls.length, 0)
      assert.equal(next.mock.calls.length, 0)
    })
  }

  void it('returns 404 for a missing basket', async () => {
    mock.method(authenticatedUsers, 'from', () => ({ data: { id: 7 } }))
    mock.method(BasketModel, 'findOne', async () => null)

    await retrieveBasket()(req, res, next)

    assert.equal(res.status.mock.calls[0].arguments[0], 404)
    assert.deepEqual(res.json.mock.calls[0].arguments[0], { status: 'error', message: 'Not found' })
  })

  for (const owner of [
    { name: 'missing owner', value: null },
    { name: 'owner with an unexpected type', value: '7' }
  ]) {
    void it('fails closed for a basket with ' + owner.name, async () => {
      mock.method(authenticatedUsers, 'from', () => ({ data: { id: 7 } }))
      mock.method(BasketModel, 'findOne', async () => ({ id: 101, UserId: owner.value, Products: [] }))

      await retrieveBasket()(req, res, next)

      assert.equal(res.status.mock.calls[0].arguments[0], 403)
      assert.deepEqual(res.json.mock.calls[0].arguments[0], { status: 'error', message: 'Forbidden' })
    })
  }

  void it('compares the owner instead of comparing basket ID with user ID', async () => {
    mock.method(authenticatedUsers, 'from', () => ({ data: { id: 101 }, bid: 101 }))
    mock.method(BasketModel, 'findOne', async () => ({ id: 101, UserId: 7, Products: [] }))

    await retrieveBasket()(req, res, next)

    assert.equal(res.status.mock.calls[0].arguments[0], 403)
    assert.deepEqual(res.json.mock.calls[0].arguments[0], { status: 'error', message: 'Forbidden' })
  })

  void it('does not treat the token basket ID as proof of ownership', async () => {
    req.params.id = '202'
    mock.method(authenticatedUsers, 'from', () => ({ data: { id: 7 }, bid: 202 }))
    mock.method(BasketModel, 'findOne', async () => ({ id: 202, UserId: 9, Products: [] }))

    await retrieveBasket()(req, res, next)

    assert.equal(res.status.mock.calls[0].arguments[0], 403)
    assert.deepEqual(res.json.mock.calls[0].arguments[0], { status: 'error', message: 'Forbidden' })
  })

  void it('forwards database errors without returning basket data', async () => {
    const error = new Error('Database failure')
    mock.method(authenticatedUsers, 'from', () => ({ data: { id: 7 } }))
    mock.method(BasketModel, 'findOne', async () => { throw error })

    await retrieveBasket()(req, res, next)

    assert.equal(next.mock.calls[0].arguments[0], error)
    assert.equal(res.json.mock.calls.length, 0)
  })
})
