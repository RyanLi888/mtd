'use strict'

const { toNumber, normalizeLevel } = require('./result-utils')

class DetectionService {
  constructor(configStore, sshManager, broadcast) {
    this.configStore = configStore
    this.sshManager = sshManager
    this.broadcast = broadcast || (() => {})
    this.timers = new Map()
    this.activeRuns = new Map()
    this.latestCpu = new Map()
    this.latestTraffic = new Map()
    this.latestRandom = new Map()
    this.statuses = new Map()
    this.riskSeries = new Map()
  }

  setStatus(serverId, status, message = '') {
    const payload = { status, timestamp: new Date().toISOString() }
    if (message) payload.message = message
    this.statuses.set(serverId, payload)
    this.broadcast('detection:status', { serverId, ...payload })
    return payload
  }

  startAll() {
    this.stopAll()
    for (const server of this.configStore.listServers()) {
      if (server.enabled) this.schedule(server)
      else this.setStatus(server.id, 'disabled')
    }
  }

  refreshServer(serverId) {
    const timer = this.timers.get(serverId)
    if (timer) clearInterval(timer)
    this.timers.delete(serverId)
    const server = this.configStore.getServer(serverId)
    if (server && server.enabled) this.schedule(server)
    else this.setStatus(serverId, 'disabled')
  }

  schedule(server) {
    const execute = () => this.run(server.id, 'all').catch(error => {
      this.setStatus(server.id, 'error', error.message)
      this.broadcast('detection:error', { serverId: server.id, message: error.message })
    })
    execute()
    const timer = setInterval(execute, server.checkInterval * 1000)
    this.timers.set(server.id, timer)
  }

  stopAll() {
    for (const timer of this.timers.values()) clearInterval(timer)
    this.timers.clear()
  }

  async run(serverId, mode = 'traffic') {
    if (['quick', 'full', 'all'].includes(mode)) return this.runAll(serverId)
    if (mode === 'cpu') return this.runCpu(serverId)
    if (mode === 'traffic') return this.runTraffic(serverId)
    if (mode === 'random') return this.runRandom(serverId)
    throw new Error('不支持的检测模式')
  }


  runExclusive(key, task) {
    const existing = this.activeRuns.get(key)
    if (existing) return existing
    const promise = (async () => task())()
      .finally(() => {
        this.activeRuns.delete(key)
      })
    this.activeRuns.set(key, promise)
    return promise
  }
  async runAll(serverId) {
    const key = `${serverId}:all`
    return this.runExclusive(key, async () => {
      this.setStatus(serverId, 'detecting')
      try {
        const result = { cpu: null, traffic: null, random: null, errors: [] }
        try {
          result.cpu = await this.sshManager.readCpuResult(serverId)
          this.latestCpu.set(serverId, result.cpu)
          this.broadcast('cpu:result', result.cpu)
        } catch (error) {
          result.errors.push(`进程：${error.message}`)
        }
        try {
          result.traffic = await this.sshManager.readTrafficAlerts(serverId)
          this.latestTraffic.set(serverId, result.traffic)
          this.broadcast('traffic:alerts', result.traffic)
        } catch (error) {
          result.errors.push(`流量：${error.message}`)
        }
        try {
          result.random = await this.sshManager.readRandomObservations(serverId)
          this.latestRandom.set(serverId, result.random)
          this.broadcast('random:observations', result.random)
        } catch (error) {
          result.errors.push(`随机探测：${error.message}`)
        }
        if (!result.cpu && !result.traffic && !result.random) throw new Error(result.errors.join('；') || '读取远程检测结果失败')
        this.setStatus(serverId, 'online')
        this.updateSeries(serverId)
        this.broadcast('detection:result', { serverId, ...result })
        return result
      } catch (error) {
        this.setStatus(serverId, 'error', error.message)
        throw error
      }
    })
  }
  async runCpu(serverId) {
    const key = `${serverId}:cpu`
    return this.runExclusive(key, async () => {
      this.setStatus(serverId, 'detecting')
      try {
        const result = await this.sshManager.readCpuResult(serverId)
        this.latestCpu.set(serverId, result)
        this.setStatus(serverId, 'online')
        this.updateSeries(serverId)
        this.broadcast('cpu:result', result)
        this.broadcast('detection:result', { serverId, cpu: result })
        return result
      } catch (error) {
        this.setStatus(serverId, 'error', error.message)
        throw error
      }
    })
  }
  async runTraffic(serverId) {
    const key = `${serverId}:traffic`
    return this.runExclusive(key, async () => {
      this.setStatus(serverId, 'detecting')
      try {
        const result = await this.sshManager.readTrafficAlerts(serverId)
        this.latestTraffic.set(serverId, result)
        this.setStatus(serverId, 'online')
        this.updateSeries(serverId)
        this.broadcast('traffic:alerts', result)
        this.broadcast('detection:result', { serverId, traffic: result })
        return result
      } catch (error) {
        this.setStatus(serverId, 'error', error.message)
        throw error
      }
    })
  }
  async runRandom(serverId) {
    const key = `${serverId}:random`
    return this.runExclusive(key, async () => {
      this.setStatus(serverId, 'detecting')
      try {
        const result = await this.sshManager.readRandomObservations(serverId)
        this.latestRandom.set(serverId, result)
        this.setStatus(serverId, 'online')
        this.broadcast('random:observations', result)
        this.broadcast('detection:result', { serverId, random: result })
        return result
      } catch (error) {
        this.setStatus(serverId, 'error', error.message)
        throw error
      }
    })
  }
  listCpuCandidates(filters = {}) {
    const servers = this.configStore.listServers()
    const rows = []
    for (const server of servers) {
      if (filters.serverId && server.id !== filters.serverId) continue
      const result = this.latestCpu.get(server.id)
      const candidates = result && Array.isArray(result.candidates) ? result.candidates : []
      for (const candidate of candidates) {
        rows.push({
          ...candidate,
          id: candidate.key || `${server.id}-${candidate.pid || candidate.name || rows.length}`,
          serverId: server.id,
          serverName: server.name,
          timestamp: candidate.last_seen || result.timestamp,
          sourcePath: result.source_path
        })
      }
    }
    return rows.sort((left, right) => new Date(right.timestamp || 0) - new Date(left.timestamp || 0))
  }

  listTrafficAlerts(filters = {}) {
    const servers = this.configStore.listServers()
    const rows = []
    for (const server of servers) {
      if (filters.serverId && server.id !== filters.serverId) continue
      const result = this.latestTraffic.get(server.id)
      const alerts = result && Array.isArray(result.alerts) ? result.alerts : []
      for (const alert of alerts) {
        const level = normalizeLevel(alert.level)
        if (filters.level && level !== filters.level) continue
        rows.push({
          ...alert,
          id: alert.id || `${server.id}-${rows.length}`,
          serverId: server.id,
          serverName: server.name,
          timestamp: alert.timestamp || result.timestamp,
          level,
          type: this.trafficType(alert),
          status: 'new',
          sourcePath: result.source_path,
          report: result
        })
      }
    }
    return rows.sort((left, right) => new Date(right.timestamp || 0) - new Date(left.timestamp || 0))
  }

  listRandomObservations(filters = {}) {
    const servers = this.configStore.listServers()
    const rows = []
    for (const server of servers) {
      if (filters.serverId && server.id !== filters.serverId) continue
      const result = this.latestRandom.get(server.id)
      const observations = result && Array.isArray(result.observations) ? result.observations : []
      for (const observation of observations) {
        if (filters.result && observation.result !== filters.result) continue
        rows.push({
          ...observation,
          id: observation.id || `${server.id}-${rows.length}`,
          serverId: server.id,
          serverName: server.name,
          timestamp: observation.timestamp || result.timestamp,
          sourcePath: observation.source_path || result.source_path,
          report: result
        })
      }
    }
    return rows.sort((left, right) => new Date(right.timestamp || 0) - new Date(left.timestamp || 0))
  }

  trafficType(alert) {
    if (alert.process) return `流量告警：${alert.process}`
    if (alert.remote_port) return `告警端口：${alert.remote_port}`
    return '流量告警'
  }

  updateSeries(serverId) {
    const points = this.riskSeries.get(serverId) || []
    points.push({
      timestamp: new Date().toISOString(),
      value: this.riskScorePercent(serverId)
    })
    this.riskSeries.set(serverId, points.slice(-120))
  }

  riskScorePercent(serverId) {
    const cpu = this.latestCpu.get(serverId)
    const traffic = this.latestTraffic.get(serverId)
    const candidates = cpu && Array.isArray(cpu.candidates) ? cpu.candidates : []
    const alerts = traffic && Array.isArray(traffic.alerts) ? traffic.alerts : []
    const levelWeight = { safe: 0, low: 25, medium: 55, high: 80, critical: 100, unknown: 40 }
    const trafficScore = alerts.reduce((max, alert) => Math.max(max, levelWeight[normalizeLevel(alert.level)] || 40), 0)
    const candidateScore = this.candidateScore(candidates)
    return Math.min(100, Math.max(trafficScore, candidateScore))
  }

  candidateScore(candidates) {
    if (!candidates.length) return 0
    let score = 10
    for (const candidate of candidates) {
      const reasons = Array.isArray(candidate.last_reasons) ? candidate.last_reasons : []
      const hitCount = toNumber(candidate.hit_count, 0)
      const hasHighCpu = reasons.includes('high_cpu')
      const hasMinerName = reasons.includes('name_suspicious')
      const hasLibssl = reasons.includes('has_libssl')
      if (hasHighCpu && hasMinerName) score = Math.max(score, 55)
      else if (hasHighCpu || hasMinerName) score = Math.max(score, 40)
      else if (hasLibssl || hitCount >= 3) score = Math.max(score, 20)
    }
    return score
  }

  riskLevelOf(serverId) {
    const score = this.riskScorePercent(serverId)
    if (score >= 90) return 'critical'
    if (score >= 70) return 'high'
    if (score >= 40) return 'medium'
    if (score > 0) return 'low'
    return 'safe'
  }

  getSummary() {
    const servers = this.configStore.listServers()
    let highestRisk = 'safe'
    let cpuCandidateCount = 0
    let trafficAlertCount = 0
    let randomObservationCount = 0
    const riskWeight = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 }
    const details = servers.map(server => {
      const latestCpu = this.latestCpu.get(server.id) || null
      const latestTraffic = this.latestTraffic.get(server.id) || null
      const latestRandom = this.latestRandom.get(server.id) || null
      const level = this.riskLevelOf(server.id)
      if (riskWeight[level] > riskWeight[highestRisk]) highestRisk = level
      cpuCandidateCount += latestCpu && Array.isArray(latestCpu.candidates) ? latestCpu.candidates.length : 0
      trafficAlertCount += latestTraffic && Array.isArray(latestTraffic.alerts) ? latestTraffic.alerts.length : 0
      randomObservationCount += latestRandom && Array.isArray(latestRandom.observations) ? latestRandom.observations.length : 0
      const runtimeStatus = server.enabled === false
        ? { status: 'disabled', timestamp: new Date().toISOString() }
        : this.statuses.get(server.id) || { status: 'offline' }
      return {
        ...server,
        runtimeStatus,
        latestCpu,
        latestTraffic,
        latestRandom,
        latest: latestTraffic,
        riskLevel: level,
        riskSeries: this.riskSeries.get(server.id) || []
      }
    })
    return {
      riskLevel: highestRisk,
      serverCount: servers.length,
      onlineCount: details.filter(item => ['online', 'connected', 'detecting', 'reconnecting'].includes(item.runtimeStatus.status)).length,
      cpuCandidateCount,
      trafficAlertCount,
      randomObservationCount,
      suspiciousProcesses: cpuCandidateCount,
      suspiciousConnections: trafficAlertCount,
      alarmCount: trafficAlertCount,
      servers: details
    }
  }
}

module.exports = { DetectionService }
