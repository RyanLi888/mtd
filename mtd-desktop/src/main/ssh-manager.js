'use strict'

const fs = require('fs')
const net = require('net')
const path = require('path')
const { Client } = require('ssh2')
const { cpuResultPathOf, trafficAlertPathOf, randomObservationPathOf } = require('./config-store')

const MAX_OUTPUT_BYTES = 2 * 1024 * 1024

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'"'"'`)}'`
}

function assertAbsoluteLinuxPath(value, label) {
  if (!/^\/[A-Za-z0-9._/ +:-]+$/.test(value) || value.includes('..')) {
    throw new Error(`${label}不是安全的 Linux 绝对路径`)
  }
}

function toArray(value) {
  if (Array.isArray(value)) return value
  if (!value || typeof value !== 'object') return []
  return Object.keys(value).map(key => ({ key, ...value[key] })).filter(item => item && typeof item === 'object')
}

function firstValue(source, keys, fallback = '') {
  for (const key of keys) {
    const value = source && source[key]
    if (value !== undefined && value !== null && value !== '') return value
  }
  return fallback
}

function toNumber(value, fallback = 0) {
  const number = Number(value)
  return Number.isFinite(number) ? number : fallback
}

function normalizeEpoch(value) {
  const number = Number(value)
  if (!Number.isFinite(number) || number <= 0) return ''
  return new Date(number * 1000).toISOString()
}

function pickArray(source, keys) {
  for (const key of keys) {
    const value = source && source[key]
    if (Array.isArray(value)) return value
  }
  return []
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

function toBoolean(value, fallback = false) {
  if (value === true || value === false) return value
  const text = String(value === undefined || value === null ? '' : value).toLowerCase()
  if (['true', '1', 'yes', 'abnormal'].includes(text)) return true
  if (['false', '0', 'no', 'normal'].includes(text)) return false
  return fallback
}

function normalizeCpuResult(raw, server, sourcePath) {
  const source = raw && raw.result && raw.result.cpu ? raw.result.cpu : raw
  const candidateRoot = source && (source.candidate_state || source.candidates || source.suspicious_processes || source.processes || source)
  const candidates = toArray(candidateRoot)
    .filter(item => item.pid !== undefined || item.name || item.exe_hash)
    .map(item => {
      const reasons = Array.isArray(item.last_reasons)
        ? item.last_reasons
        : Array.isArray(item.reasons) ? item.reasons : []
      const candidate = {
        key: String(firstValue(item, ['key', 'id'], '')),
        pid: firstValue(item, ['pid'], null),
        name: String(firstValue(item, ['name', 'process', 'process_name'], 'unknown')),
        cpu: firstValue(item, ['cpu', 'cpu_percent', 'cpuPercent'], null),
        memory: firstValue(item, ['memory', 'memory_percent', 'memoryPercent'], null),
        command: String(firstValue(item, ['command', 'cmdline', 'cmd'], '')),
        create_time: firstValue(item, ['create_time', 'createTime'], null),
        create_time_iso: String(firstValue(item, ['create_time_iso', 'createTimeIso', 'create_time_utc'], '')),
        exe_hash: String(firstValue(item, ['exe_hash', 'exeHash', 'hash'], '')),
        hit_count: toNumber(firstValue(item, ['hit_count', 'hitCount'], 1), 1),
        first_seen: String(firstValue(item, ['first_seen', 'firstSeen'], '')),
        last_seen: String(firstValue(item, ['last_seen', 'lastSeen'], '')),
        last_seen_ts: firstValue(item, ['last_seen_ts', 'lastSeenTs'], null),
        last_reasons: reasons,
        raw: item
      }
      candidate.create_time_iso = candidate.create_time_iso || normalizeEpoch(candidate.create_time)
      candidate.last_seen = candidate.last_seen || normalizeEpoch(candidate.last_seen_ts)
      return candidate
    })
    .sort((left, right) => toNumber(right.hit_count) - toNumber(left.hit_count))

  return {
    status: 'ok',
    timestamp: firstValue(raw, ['timestamp', 'time'], '') || candidates[0] && candidates[0].last_seen || new Date().toISOString(),
    server_id: server.id,
    server_name: server.name || server.id,
    source_path: sourcePath,
    candidates,
    total: candidates.length,
    raw
  }
}

function normalizeTrafficAlerts(raw, server, sourcePath) {
  const source = raw && raw.result && raw.result.network ? raw.result.network : raw
  const direct = Array.isArray(source) ? source : []
  const nested = pickArray(source || {}, ['suspicious_connections', 'connections', 'alerts', 'alarms', 'traffic', 'items', 'data', 'rows'])
  const objectValues = !direct.length && !nested.length ? toArray(source) : []
  const alerts = (direct.length ? direct : nested.length ? nested : objectValues)
    .filter(item => item && typeof item === 'object')
    .map((item, index) => ({
      id: String(firstValue(item, ['id', 'trafficId', 'alert_id'], `${server.id}-${index}`)),
      timestamp: String(firstValue(item, ['trafficTime', 'traffic_time', 'timestamp', 'time'], '')),
      source_ip: String(firstValue(item, ['sourceIp', 'source_ip', 'src_ip', 'src', 'local_ip'], '')),
      destination_ip: String(firstValue(item, ['destinationIp', 'destination_ip', 'dst_ip', 'dst', 'remote_ip', 'ip', 'target_ip'], '')),
      remote_ip: String(firstValue(item, ['remote_ip', 'destinationIp', 'destination_ip', 'dst_ip', 'dst', 'ip', 'target_ip'], '')),
      remote_port: firstValue(item, ['remote_port', 'destinationPort', 'destination_port', 'dst_port', 'port'], ''),
      protocol: String(firstValue(item, ['protocol', 'proto'], '')),
      state: String(firstValue(item, ['state', 'status'], '')),
      process: String(firstValue(item, ['process', 'process_name', 'name'], '')),
      pid: firstValue(item, ['pid'], null),
      level: normalizeLevel(firstValue(item, ['level', 'threatLevel', 'threat_level'], '')),
      raw: item
    }))

  return {
    status: 'ok',
    timestamp: firstValue(raw, ['timestamp', 'time'], '') || alerts[0] && alerts[0].timestamp || new Date().toISOString(),
    server_id: server.id,
    server_name: server.name || server.id,
    source_path: sourcePath,
    alerts,
    total: alerts.length,
    raw
  }
}

function normalizeRandomObservations(raw, server, sourcePath) {
  const source = raw && raw.result && raw.result.random ? raw.result.random : raw
  const direct = Array.isArray(source) ? source : []
  const nested = pickArray(source || {}, ['random_observations', 'observations', 'items', 'data', 'rows'])
  const objectValues = !direct.length && !nested.length ? toArray(source) : []
  const observations = (direct.length ? direct : nested.length ? nested : objectValues)
    .filter(item => item && typeof item === 'object')
    .map((item, index) => {
      const parseError = String(item.__parse_error || '')
      const result = String(firstValue(item, ['result', 'status'], '')).toLowerCase()
      const isAbnormal = parseError ? false : toBoolean(firstValue(item, ['is_abnormal', 'isAbnormal'], result), result === 'abnormal')
      const timestamp = String(firstValue(item, ['timestamp', 'time', 'created_at', 'createdAt', 'probe_end', 'probeEnd', 'end_time'], '')) || item.__mtime || ''
      return {
        id: String(firstValue(item, ['id', 'observation_id'], `${server.id}-${item.__file_name || index}`)),
        schema_version: String(firstValue(item, ['schema_version', 'schemaVersion'], '')),
        record_type: String(firstValue(item, ['record_type', 'recordType'], '')),
        timestamp,
        result: parseError ? 'parse_error' : result || (isAbnormal ? 'abnormal' : 'normal'),
        is_abnormal: isAbnormal,
        pid: firstValue(item, ['pid'], null),
        process_name: String(firstValue(item, ['process_name', 'processName', 'process', 'name'], '')),
        process_user: String(firstValue(item, ['process_user', 'processUser', 'user', 'username'], '')),
        exe_path: String(firstValue(item, ['exe_path', 'exePath', 'path'], '')),
        exe_hash: String(firstValue(item, ['exe_hash', 'exeHash', 'hash'], '')),
        cmdline_hash: String(firstValue(item, ['cmdline_hash', 'cmdlineHash', 'command_hash'], '')),
        verdict: String(firstValue(item, ['verdict', 'decision', 'message'], '')),
        confidence: String(firstValue(item, ['confidence'], '')),
        visibility_mode: String(firstValue(item, ['visibility_mode', 'visibilityMode'], '')),
        visibility_boundary: String(firstValue(item, ['visibility_boundary', 'visibilityBoundary'], '')),
        reasons: Array.isArray(item.reasons) ? item.reasons : [],
        evidence: item.evidence && typeof item.evidence === 'object' ? item.evidence : {},
        observation: item.observation && typeof item.observation === 'object' ? item.observation : {},
        privacy: item.privacy && typeof item.privacy === 'object' ? item.privacy : {},
        note: String(firstValue(item, ['note', 'description'], '')),
        file_name: String(item.__file_name || ''),
        source_path: String(item.__source_path || sourcePath),
        parse_error: parseError,
        raw: item
      }
    })
    .sort((left, right) => new Date(right.timestamp || 0) - new Date(left.timestamp || 0))

  return {
    status: 'ok',
    timestamp: observations[0] && observations[0].timestamp || new Date().toISOString(),
    server_id: server.id,
    server_name: server.name || server.id,
    source_path: sourcePath,
    observations,
    total: observations.length,
    raw
  }
}

function parseRemoteData(text, label) {
  const value = String(text || '').trim()
  if (!value) return []
  try {
    return JSON.parse(value)
  } catch (jsonError) {
    const lines = value.split(/\r?\n/).map(line => line.trim()).filter(Boolean)
    const records = []
    try {
      for (const line of lines) records.push(JSON.parse(line))
      if (records.length) return records
    } catch (jsonlError) {
      throw new Error(`${label}不是有效 JSON 或 JSONL：${jsonError.message}`)
    }
    throw new Error(`${label}不是有效 JSON 或 JSONL：${jsonError.message}`)
  }
}

class SshManager {
  constructor(configStore, onStatus) {
    this.configStore = configStore
    this.onStatus = onStatus || (() => {})
    this.connections = new Map()
    this.streams = new Map()
  }

  async connect(serverId) {
    const existing = this.connections.get(serverId)
    if (existing && existing.ready) return existing.client
    if (existing && existing.promise) return existing.promise

    const server = this.configStore.getServer(serverId, true)
    if (!server) throw new Error('服务器配置不存在')

    const client = new Client()
    const state = { client, ready: false, promise: null, reconnectAttempt: 0, closedByUser: false }
    state.promise = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        client.end()
        reject(new Error('SSH 连接超时'))
      }, 15000)

      client.once('ready', () => {
        clearTimeout(timeout)
        state.ready = true
        state.promise = null
        state.reconnectAttempt = 0
        this.startHeartbeat(serverId)
        this.emitStatus(serverId, 'connected')
        resolve(client)
      })
      client.once('error', error => {
        clearTimeout(timeout)
        if (!state.ready) {
          state.promise = null
          this.connections.delete(serverId)
          reject(new Error(`SSH 连接失败：${error.message}`))
        }
        this.emitStatus(serverId, 'error', error.message)
      })
      client.on('close', () => {
        state.ready = false
        this.stopHeartbeat(state)
        this.emitStatus(serverId, 'disconnected')
        if (!state.closedByUser && server.enabled) this.scheduleReconnect(serverId, state)
      })
    })

    this.connections.set(serverId, state)
    const options = this.connectionOptions(server)
    client.connect(options)
    return state.promise
  }

  connectionOptions(server) {
    const options = {
      host: server.host,
      port: server.port,
      username: server.username,
      readyTimeout: 15000,
      keepaliveInterval: 10000,
      keepaliveCountMax: 3
    }
    if (server.authType === 'password') {
      options.password = server.password
    } else {
      options.privateKey = fs.readFileSync(path.resolve(server.identityFile))
    }
    if (server.hostFingerprint) {
      options.hostHash = 'sha256'
      options.hostVerifier = fingerprint => fingerprint === server.hostFingerprint
    } else if (!server.allowUntrustedHost) {
      throw new Error('首次连接前请填写主机 SHA-256 指纹，或显式允许未验证主机')
    }
    return options
  }

  async disconnect(serverId) {
    this.stopStream(serverId)
    const state = this.connections.get(serverId)
    if (!state) return
    state.closedByUser = true
    this.stopHeartbeat(state)
    state.client.end()
    this.connections.delete(serverId)
    this.emitStatus(serverId, 'disconnected')
  }

  async disconnectAll() {
    await Promise.all([...this.connections.keys()].map(id => this.disconnect(id)))
  }

  async testConnection(serverId) {
    const started = Date.now()
    await this.connect(serverId)
    const server = this.configStore.getServer(serverId)
    if (!server) throw new Error('服务器配置不存在')
    const cpuResultPath = cpuResultPathOf(server)
    const trafficAlertPath = trafficAlertPathOf(server)
    const randomObservationPath = randomObservationPathOf(server)
    assertAbsoluteLinuxPath(server.projectPath, '远程项目路径')
    assertAbsoluteLinuxPath(cpuResultPath, '进程候选状态路径')
    assertAbsoluteLinuxPath(trafficAlertPath, '流量告警路径')
    assertAbsoluteLinuxPath(randomObservationPath, '随机探测目录')
    const command = `test -d ${shellQuote(server.projectPath)} && printf 'project-ok'; test -f ${shellQuote(cpuResultPath)} && printf ':cpu-ok'; test -f ${shellQuote(trafficAlertPath)} && printf ':traffic-ok'; test -d ${shellQuote(randomObservationPath)} && printf ':random-ok'`
    const output = await this.exec(serverId, command)
    if (!output.stdout.startsWith('project-ok')) throw new Error(`远程项目目录不存在：${server.projectPath}`)
    const cpuResultExists = output.stdout.includes(':cpu-ok')
    const trafficAlertExists = output.stdout.includes(':traffic-ok')
    const randomObservationExists = output.stdout.includes(':random-ok')
    return {
      ok: true,
      latency: Date.now() - started,
      projectPath: server.projectPath,
      cpuResultPath,
      trafficAlertPath,
      randomObservationPath,
      cpuResultExists,
      trafficAlertExists,
      randomObservationExists,
      resultExists: cpuResultExists || trafficAlertExists || randomObservationExists
    }
  }

  async readRemoteJson(serverId, sourcePath, label) {
    assertAbsoluteLinuxPath(sourcePath, `${label}路径`)
    const command = `test -f ${shellQuote(sourcePath)} || { printf '%s' '${label}文件不存在' >&2; exit 4; }; cat -- ${shellQuote(sourcePath)}`
    const settings = this.configStore.getSettings().detection
    const output = await this.exec(serverId, command, settings.timeout * 1000)
    if (output.code !== 0) throw new Error(output.stderr.trim() || `读取${label}失败，退出码：${output.code}`)
    return parseRemoteData(output.stdout.trim(), `${label}文件`)
  }

  async readRemoteJsonDirectory(serverId, sourceDir, label) {
    assertAbsoluteLinuxPath(sourceDir, `${label}目录`)
    const client = await this.connect(serverId)
    const sftp = await new Promise((resolve, reject) => {
      client.sftp((error, instance) => error ? reject(error) : resolve(instance))
    })
    try {
      const entries = await new Promise((resolve, reject) => {
        sftp.readdir(sourceDir, (error, list) => error ? reject(new Error(`${label}目录不存在或不可读取：${error.message}`)) : resolve(list || []))
      })
      const files = entries
        .filter(entry => {
          const name = String(entry.filename || '')
          const attrs = entry.attrs || {}
          const isFile = typeof attrs.isFile === 'function' ? attrs.isFile() : true
          return isFile && name.endsWith('.json')
        })
        .sort((left, right) => toNumber(right.attrs && right.attrs.mtime) - toNumber(left.attrs && left.attrs.mtime))
        .slice(0, 200)
      const records = []
      for (const entry of files) {
        const filePath = path.posix.join(sourceDir, entry.filename)
        const mtime = entry.attrs && entry.attrs.mtime ? new Date(entry.attrs.mtime * 1000).toISOString() : ''
        const buffer = await new Promise((resolve, reject) => {
          sftp.readFile(filePath, (error, data) => error ? reject(new Error(`读取${label}文件失败：${entry.filename}：${error.message}`)) : resolve(data))
        })
        if (Buffer.byteLength(buffer) > MAX_OUTPUT_BYTES) {
          records.push({ __file_name: entry.filename, __source_path: filePath, __mtime: mtime, __parse_error: '文件超过 2MB 限制' })
          continue
        }
        try {
          const parsed = parseRemoteData(buffer.toString('utf8'), `${label}文件 ${entry.filename}`)
          const items = Array.isArray(parsed) ? parsed : [parsed]
          for (const item of items) {
            const record = item && typeof item === 'object' ? item : { value: item }
            records.push({ ...record, __file_name: entry.filename, __source_path: filePath, __mtime: mtime })
          }
        } catch (error) {
          records.push({ __file_name: entry.filename, __source_path: filePath, __mtime: mtime, __parse_error: error.message })
        }
      }
      return records
    } finally {
      if (typeof sftp.end === 'function') sftp.end()
    }
  }

  async readCpuResult(serverId) {
    const server = this.configStore.getServer(serverId)
    if (!server) throw new Error('服务器配置不存在')
    const sourcePath = cpuResultPathOf(server)
    const raw = await this.readRemoteJson(serverId, sourcePath, '进程候选状态')
    return normalizeCpuResult(raw, server, sourcePath)
  }

  async readTrafficAlerts(serverId) {
    const server = this.configStore.getServer(serverId)
    if (!server) throw new Error('服务器配置不存在')
    const sourcePath = trafficAlertPathOf(server)
    const raw = await this.readRemoteJson(serverId, sourcePath, '流量告警')
    return normalizeTrafficAlerts(raw, server, sourcePath)
  }

  async readRandomObservations(serverId) {
    const server = this.configStore.getServer(serverId)
    if (!server) throw new Error('服务器配置不存在')
    const sourcePath = randomObservationPathOf(server)
    const raw = await this.readRemoteJsonDirectory(serverId, sourcePath, '随机探测结果')
    return normalizeRandomObservations(raw, server, sourcePath)
  }

  async runDetection(serverId, mode = 'traffic') {
    if (mode === 'cpu') return this.readCpuResult(serverId)
    if (mode === 'traffic') return this.readTrafficAlerts(serverId)
    if (mode === 'random') return this.readRandomObservations(serverId)
    return {
      cpu: await this.readCpuResult(serverId),
      traffic: await this.readTrafficAlerts(serverId),
      random: await this.readRandomObservations(serverId)
    }
  }

  async remediate(serverId, request) {
    if (!request || request.confirmed !== true) throw new Error('处置操作必须经过二次确认')
    const settings = this.configStore.getSettings().detection
    const scriptRoot = path.posix.dirname(settings.scriptPath)
    assertAbsoluteLinuxPath(scriptRoot, '检测程序目录')

    const definitions = {
      kill_process: { script: 'remediate_kill.sh', validate: value => /^\d{1,10}$/.test(value) && Number(value) > 100 },
      block_ip: { script: 'remediate_ip.sh', validate: value => net.isIP(value) !== 0 },
      isolate_file: { script: 'remediate_isolate.sh', validate: value => /^\/[A-Za-z0-9._/ +:-]+$/.test(value) && !value.includes('..') }
    }
    const definition = definitions[request.action]
    const target = String(request.target || '').trim()
    if (!definition || !definition.validate(target)) throw new Error('处置动作或目标格式无效')
    const scriptPath = path.posix.join(scriptRoot, 'scripts', definition.script)
    const command = `sudo ${shellQuote(scriptPath)} ${shellQuote(target)}`
    const output = await this.exec(serverId, command, 20000)
    if (output.code !== 0) throw new Error(output.stderr.trim() || '远程处置失败')
    return { ok: true, output: output.stdout.trim() }
  }

  async startStream(serverId, onData) {
    this.stopStream(serverId)
    const settings = this.configStore.getSettings().detection
    assertAbsoluteLinuxPath(settings.streamLogPath, '流式日志路径')
    const client = await this.connect(serverId)
    const command = `tail -n 0 -F -- ${shellQuote(settings.streamLogPath)}`
    return new Promise((resolve, reject) => {
      client.exec(command, (error, stream) => {
        if (error) return reject(error)
        this.streams.set(serverId, stream)
        let buffer = ''
        stream.on('data', chunk => {
          buffer += chunk.toString('utf8')
          const lines = buffer.split(/\r?\n/)
          buffer = lines.pop() || ''
          lines.filter(Boolean).forEach(line => {
            let payload = line
            try { payload = JSON.parse(line) } catch (_) { /* plain log line */ }
            onData({ serverId, payload, timestamp: new Date().toISOString() })
          })
        })
        stream.on('close', () => this.streams.delete(serverId))
        stream.on('error', error => this.emitStatus(serverId, 'error', error.message))
        resolve({ started: true })
      })
    })
  }

  stopStream(serverId) {
    const stream = this.streams.get(serverId)
    if (stream) stream.close()
    this.streams.delete(serverId)
    return { stopped: true }
  }

  async exec(serverId, command, timeoutMs = 30000) {
    const client = await this.connect(serverId)
    return new Promise((resolve, reject) => {
      let settled = false
      const timer = setTimeout(() => finish(new Error('远程命令执行超时')), timeoutMs)
      const finish = (error, result) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        if (error) reject(error)
        else resolve(result)
      }

      client.exec(command, (error, stream) => {
        if (error) return finish(error)
        let stdout = ''
        let stderr = ''
        const append = (current, chunk) => {
          const next = current + chunk.toString('utf8')
          if (Buffer.byteLength(next, 'utf8') > MAX_OUTPUT_BYTES) {
            stream.close()
            finish(new Error('远程命令输出超过 2MB 限制'))
          }
          return next
        }
        stream.on('data', chunk => { stdout = append(stdout, chunk) })
        stream.stderr.on('data', chunk => { stderr = append(stderr, chunk) })
        stream.on('close', code => finish(null, { code, stdout, stderr }))
        stream.on('error', finish)
      })
    })
  }

  startHeartbeat(serverId) {
    const state = this.connections.get(serverId)
    if (!state || state.heartbeat) return
    state.heartbeat = setInterval(() => {
      if (state.ready) this.exec(serverId, "printf 'keepalive'", 5000).catch(() => state.client.end())
    }, 30000)
  }

  stopHeartbeat(state) {
    if (state.heartbeat) clearInterval(state.heartbeat)
    state.heartbeat = null
  }

  scheduleReconnect(serverId, state) {
    state.reconnectAttempt += 1
    const delay = Math.min(60000, 1000 * (2 ** Math.min(state.reconnectAttempt, 6)))
    setTimeout(() => {
      this.connections.delete(serverId)
      this.connect(serverId).catch(error => this.emitStatus(serverId, 'reconnecting', error.message))
    }, delay)
  }

  emitStatus(serverId, status, message = '') {
    this.onStatus({ serverId, status, message, timestamp: new Date().toISOString() })
  }
}

module.exports = { SshManager }