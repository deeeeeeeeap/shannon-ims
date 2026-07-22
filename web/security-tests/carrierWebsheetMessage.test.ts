import test from 'node:test'
import assert from 'node:assert/strict'
import { validateCarrierWebsheetMessage } from '../src/components/carrierWebsheetMessage'

test('callback schema requires own source and event fields', () => {
  const iframeWindow = {}
  Object.defineProperties(Object.prototype, {
    source: {
      configurable: true,
      value: 'vowifi'
    },
    event: {
      configurable: true,
      value: 'dismissFlow'
    }
  })

  try {
    const callback = validateCarrierWebsheetMessage(
      {
        origin: 'null',
        source: iframeWindow,
        data: {
          type: 'vohive-websheet-callback',
          sessionId: 'synthetic-session',
          nonce: 'synthetic-nonce',
          callback: {}
        }
      },
      {
        iframeWindow,
        sessionId: 'synthetic-session',
        nonce: 'synthetic-nonce'
      }
    )

    assert.equal(callback, null, 'schema accepted inherited required fields')
  } finally {
    delete (Object.prototype as { source?: unknown }).source
    delete (Object.prototype as { event?: unknown }).event
  }
})

function validFixture() {
  const iframeWindow = {}
  const context = {
    iframeWindow,
    sessionId: 'synthetic-session',
    nonce: 'synthetic-nonce'
  }
  const data = {
    type: 'vohive-websheet-callback',
    sessionId: context.sessionId,
    nonce: context.nonce,
    callback: {
      source: 'vowifi',
      event: 'dismissFlow'
    }
  }
  return {
    context,
    event: {
      origin: 'null',
      source: iframeWindow,
      data
    }
  }
}

test('exact iframe message returns the validated callback', () => {
  const fixture = validFixture()
  const callback = validateCarrierWebsheetMessage(fixture.event, fixture.context)
  assert.deepEqual(callback, { source: 'vowifi', event: 'dismissFlow' })
})

test('forged origin, source, session nonce, or schema is rejected', () => {
  const fixture = validFixture()
  const base = fixture.event
  const data = base.data
  const attempts = [
    {
      name: 'origin',
      event: { ...base, origin: 'http://127.0.0.1' }
    },
    {
      name: 'source',
      event: { ...base, source: {} }
    },
    {
      name: 'session',
      event: { ...base, data: { ...data, sessionId: 'other-session' } }
    },
    {
      name: 'nonce',
      event: { ...base, data: { ...data, nonce: 'other-nonce' } }
    },
    {
      name: 'top-level schema',
      event: { ...base, data: { ...data, unexpected: true } }
    },
    {
      name: 'callback schema',
      event: {
        ...base,
        data: {
          ...data,
          callback: { ...data.callback, unexpected: true }
        }
      }
    },
    {
      name: 'control character',
      event: {
        ...base,
        data: {
          ...data,
          callback: { ...data.callback, event: 'dismiss\u007fFlow' }
        }
      }
    }
  ]

  for (const attempt of attempts) {
    assert.equal(
      validateCarrierWebsheetMessage(attempt.event, fixture.context),
      null,
      `accepted forged ${attempt.name}`
    )
  }
})
