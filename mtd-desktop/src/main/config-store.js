'use strict'

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

const DEFAULT_CONFIG = {
  servers: [],
  detection: {
    pythonPath: '/opt/miner_detector/.venv/bin/python',
    scriptPath: '/opt/miner_detector/detector.py',
    quickMode: '--mode=quick',
    fullMode: '--mode=full',
    timeout: 30,
    streamLogPath: '/opt/miner_detector/data/logs/stream.log'
  },
  alert: {
    cpuThreshold: 80,
    autoRemediation: false
  },
  alarms: []
}

const DEFAULT_PROJECT_PATH = '/opt/miner_detector'
const DEFAULT_CPU_RESULT_FILE = 'results/candidate_state.json'
const DEFAULT_TRAFFIC_ALERT_FILE = 'results/alerts.jsonl'
const DEFAULT_RANDOM_OBSERVATION_DIR = 'results/random_observations'

function normalizeRelativeFile(value, fallback) {
  return String(value || fallback).trim().replace(/^\.\//, '')
}

function normalizeRelativeDir(value, fallback) {
  return String(value || fallback).trim().replace(/^\.\//, '').replace(/\/+$/, '')
}

function assertSafeRelativeFile(value, label) {
  if (
    !/^[A-Za-z0-9._/ +:-]+$/.test(value) ||
    value.startsWith('/') ||
    value.split('/').includes('..') ||
    !path.posix.basename(value).includes('.')
  ) {
    throw new Error(`${label}必须是项目内的安全相对文件路径`)
  }
}

function assertSafeRelativeDir(value, label) {
  if (
    !value ||
    !/^[A-Za-z0-9._/ +:-]+$/.test(value) ||
    value.startsWith('/') ||
    value.split('/').includes('..')
  ) {
    throw new Error(`${label}必须是项目内的安全相对目录路径`)
  }
}

function cpuResultPathOf(server) {
  return path.posix.join(server.projectPath, server.cpuResultFile)
}

function trafficAlertPathOf(server) {
  return path.posix.join(server.projectPath, server.trafficAlertFile)
}

function randomObservationPathOf(server) {
  return path.posix.join(server.projectPath, server.randomObservationDir)
}

class ConfigStore {
  constructor(userDataPath, safeStorage) {
    this.filePath = path.join(userDataPath, 'mtd-client.json')
    this.safeStorage = safeStorage
    this.data = this.load()
  }

  load() {
    try {
      const parsed = JSON.parse(fs.readFileSync(this.filePath, 'utf8'))
      return {
        ...DEFAULT_CONFIG,
        ...parsed,
        detection: { ...DEFAULT_CONFIG.detection, ...(parsed.detection || {}) },
        alert: { ...DEFAULT_CONFIG.alert, ...(parsed.alert || {}) },
        servers: Array.isArray(parsed.servers) ? parsed.servers.map(server => ({
          ...server,
          projectPath: server.projectPath || DEFAULT_PROJECT_PATH,
          cpuResultFile: server.cpuResultFile || server.cpuResultRelativePath || DEFAULT_CPU_RESULT_FILE,
          trafficAlertFile: server.trafficAlertFile || server.trafficAlertRelativePath || server.resultRelativePath || DEFAULT_TRAFFIC_ALERT_FILE,
          randomObservationDir: server.randomObservationDir || server.randomObservationRelativePath || DEFAULT_RANDOM_OBSERVATION_DIR
        })) : [],
        alarms: Array.isArray(parsed.alarms) ? parsed.alarms : []
      }
    } catch (error) {
      if (error.code !== 'ENOENT') {
        console.error('读取客户端配置失败，将使用默认配置：', error.message)
      }
      return JSON.parse(JSON.stringify(DEFAULT_CONFIG))
    }
  }

  save() {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true })
    const temporary = `${this.filePath}.tmp`
    fs.writeFileSync(temporary, JSON.stringify(this.data, null, 2), 'utf8')
    fs.renameSync(temporary, this.filePath)
  }

  listServers() {
    return this.data.servers.map(server => this.toPublicServer(server))
  }

  getServer(serverId, includeSecret = false) {
    const server = this.data.servers.find(item => item.id === serverId)
    if (!server) return null
    return includeSecret ? this.withDecryptedPassword(server) : this.toPublicServer(server)
  }

  upsertServer(input) {
    const normalized = this.normalizeServer(input)
    const index = this.data.servers.findIndex(item => item.id === normalized.id)
    const previous = index >= 0 ? this.data.servers[index] : null

    if (!normalized.passwordEncrypted && previous && previous.passwordEncrypted) {
      normalized.passwordEncrypted = previous.passwordEncrypted
    }
    if (index >= 0) this.data.servers.splice(index, 1, normalized)
    else this.data.servers.push(normalized)
    this.save()
    return this.toPublicServer(normalized)
  }

  removeServer(serverId) {
    const before = this.data.servers.length
    this.data.servers = this.data.servers.filter(item => item.id !== serverId)
    if (this.data.servers.length !== before) this.save()
    return this.data.servers.length !== before
  }

  appendAlarm(alarm) {
    this.data.alarms.unshift(alarm)
    this.data.alarms = this.data.alarms.slice(0, 1000)
    this.save()
  }

  listAlarms(filters = {}) {
    return this.data.alarms.filter(alarm => {
      if (filters.serverId && alarm.serverId !== filters.serverId) return false
      if (filters.level && alarm.level !== filters.level) return false
      if (filters.status && alarm.status !== filters.status) return false
      return true
    })
  }

  getSettings() {
    return {
      detection: { ...this.data.detection },
      alert: { ...this.data.alert }
    }
  }

  normalizeServer(input) {
    const host = String(input.host || '').trim()
    const username = String(input.username || '').trim()
    const port = Number(input.port || 22)
    const checkInterval = Math.max(2, Math.min(300, Number(input.checkInterval || 5)))
    const projectPath = String(input.projectPath || '').trim().replace(/\/+$/, '')
    const cpuResultFile = normalizeRelativeFile(input.cpuResultFile || input.cpuResultRelativePath, DEFAULT_CPU_RESULT_FILE)
    const trafficAlertFile = normalizeRelativeFile(input.trafficAlertFile || input.trafficAlertRelativePath || input.resultRelativePath, DEFAULT_TRAFFIC_ALERT_FILE)
    const randomObservationDir = normalizeRelativeDir(input.randomObservationDir || input.randomObservationRelativePath, DEFAULT_RANDOM_OBSERVATION_DIR)
    if (!host || host.length > 255) throw new Error('服务器地址不能为空或过长')
    if (!username || !/^[A-Za-z0-9._-]{1,64}$/.test(username)) throw new Error('SSH 用户名格式无效')
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('SSH 端口无效')
    if (!/^\/[A-Za-z0-9._/ +:-]+$/.test(projectPath) || projectPath.includes('..')) throw new Error('远程项目路径必须是安全的 Linux 绝对路径')
    assertSafeRelativeFile(cpuResultFile, '进程候选状态文件')
    assertSafeRelativeFile(trafficAlertFile, '流量告警文件')
    assertSafeRelativeDir(randomObservationDir, '随机探测目录')

    const server = {
      id: input.id || crypto.randomUUID(),
      name: String(input.name || host).trim().slice(0, 80),
      host,
      port,
      username,
      projectPath,
      cpuResultFile,
      trafficAlertFile,
      randomObservationDir,
      authType: input.authType === 'password' ? 'password' : 'key',
      identityFile: String(input.identityFile || '').trim(),
      enabled: input.enabled !== false,
      checkInterval,
      hostFingerprint: String(input.hostFingerprint || '').trim(),
      allowUntrustedHost: input.allowUntrustedHost === true,
      passwordEncrypted: ''
    }

    if (input.password) {
      if (!this.safeStorage || !this.safeStorage.isEncryptionAvailable()) {
        throw new Error('系统安全存储不可用，不能保存密码；请改用 SSH 密钥')
      }
      server.passwordEncrypted = this.safeStorage.encryptString(String(input.password)).toString('base64')
    }
    if (server.authType === 'key' && !server.identityFile) throw new Error('请选择 SSH 私钥文件')
    return server
  }

  withDecryptedPassword(server) {
    const result = { ...server }
    if (result.passwordEncrypted) {
      result.password = this.safeStorage.decryptString(Buffer.from(result.passwordEncrypted, 'base64'))
    }
    delete result.passwordEncrypted
    delete result.resultRelativePath
    return result
  }

  toPublicServer(server) {
    const result = {
      ...server,
      cpuResultPath: cpuResultPathOf(server),
      trafficAlertPath: trafficAlertPathOf(server),
      randomObservationPath: randomObservationPathOf(server),
      hasPassword: Boolean(server.passwordEncrypted)
    }
    delete result.passwordEncrypted
    delete result.password
    delete result.resultRelativePath
    delete result.cpuResultRelativePath
    delete result.trafficAlertRelativePath
    delete result.randomObservationRelativePath
    return result
  }
}

module.exports = {
  ConfigStore,
  DEFAULT_CONFIG,
  DEFAULT_PROJECT_PATH,
  DEFAULT_CPU_RESULT_FILE,
  DEFAULT_TRAFFIC_ALERT_FILE,
  DEFAULT_RANDOM_OBSERVATION_DIR,
  cpuResultPathOf,
  trafficAlertPathOf,
  randomObservationPathOf
}