'use strict'

function toNumber(value, fallback = 0) {
  const number = Number(value)
  return Number.isFinite(number) ? number : fallback
}

function normalizeLevel(value) {
  const text = String(value === undefined || value === null ? '' : value).toLowerCase()
  if (['critical', 'high', 'medium', 'low', 'safe'].includes(text)) return text
  if (text === '3') return 'critical'
  if (text === '2') return 'high'
  if (text === '1') return 'medium'
  if (text === '0') return 'low'
  return text || 'unknown'
}

module.exports = { toNumber, normalizeLevel }
