<template>
  <div class="remote-dashboard">
    <el-alert
      v-if="!desktop"
      title="当前为浏览器模式"
      description="SSH 检测能力只在打包后的 MTD Windows 客户端中启用。"
      type="warning"
      show-icon
      :closable="false"
      class="mode-alert"
    />

    <section class="dashboard-hero">
      <div>
        <span class="eyebrow">REMOTE MINING DEFENSE</span>
        <h1>远程挖矿检测中心</h1>
        <p>通过 SSH 安全通道读取进程候选、流量告警与随机探测结果，分别展示不同检测视图。</p>
      </div>
      <div class="hero-actions">
        <el-select v-model="selectedServerId" placeholder="选择服务器" size="medium">
          <el-option v-for="server in summary.servers" :key="server.id" :label="server.name" :value="server.id" />
        </el-select>
        <el-button type="primary" icon="el-icon-refresh" :loading="detecting" @click="runDetection('quick')">获取全部结果</el-button>
      </div>
    </section>

    <section class="metrics">
      <div class="metric-card risk-card" :class="`risk-${summary.riskLevel}`">
        <div class="metric-icon"><i class="el-icon-warning-outline" /></div>
        <div><span>总体状态</span><strong>{{ statusText(summary.riskLevel) }}</strong></div>
      </div>
      <div class="metric-card">
        <div class="metric-icon blue"><i class="el-icon-connection" /></div>
        <div><span>在线服务器</span><strong>{{ summary.onlineCount }} / {{ summary.serverCount }}</strong></div>
      </div>
      <div class="metric-card">
        <div class="metric-icon amber"><i class="el-icon-cpu" /></div>
        <div><span>候选进程</span><strong>{{ summary.cpuCandidateCount }}</strong></div>
      </div>
      <div class="metric-card">
        <div class="metric-icon violet"><i class="el-icon-link" /></div>
        <div><span>流量告警</span><strong>{{ summary.trafficAlertCount }}</strong></div>
      </div>
      <div class="metric-card">
        <div class="metric-icon blue"><i class="el-icon-view" /></div>
        <div><span>随机探测</span><strong>{{ summary.randomObservationCount }}</strong></div>
      </div>
    </section>

    <section class="content-grid">
      <div class="panel chart-panel">
        <div class="panel-heading">
          <div><span>随机探测分析</span><h3>正常 / 异常分布</h3></div>
          <span class="last-time">{{ lastDetectionTime }}</span>
        </div>
        <div v-if="randomPieTotal" class="pie-layout">
          <div ref="randomPieChart" class="random-pie-chart" />
          <div class="pie-summary">
            <div class="pie-summary-item normal"><span>正常</span><strong>{{ normalRandomCount }}</strong></div>
            <div class="pie-summary-item abnormal"><span>异常</span><strong>{{ abnormalRandomCount }}</strong></div>
          </div>
        </div>
        <el-empty v-else class="risk-empty" description="暂无随机探测结果，获取结果后展示正常/异常分布" :image-size="90" />
      </div>

      <div class="panel server-panel">
        <div class="panel-heading"><div><span>服务器状态</span><h3>服务器状态</h3></div></div>
        <div v-if="summary.servers.length" class="server-list">
          <div v-for="server in summary.servers" :key="server.id" class="server-row" @click="selectedServerId = server.id">
            <span class="status-dot" :class="server.runtimeStatus.status" />
            <div class="server-info"><strong>{{ server.name }}</strong><small>{{ server.host }}:{{ server.port }}</small></div>
            <div class="server-risk">{{ serverRisk(server) }}</div>
          </div>
        </div>
        <el-empty v-else description="请先添加远程服务器" :image-size="90">
          <el-button type="primary" size="small" @click="$router.push('/remote/servers')">添加服务器</el-button>
        </el-empty>
      </div>
    </section>

    <section class="panel alarms-panel">
      <div class="panel-heading">
        <div><span>最近告警</span><h3>最近告警</h3></div>
        <el-button type="text" @click="$router.push('/remote/alarms')">查看全部 <i class="el-icon-right" /></el-button>
      </div>
      <el-table :data="recentAlarms" empty-text="暂无告警">
        <el-table-column prop="timestamp" label="时间" min-width="165"><template slot-scope="scope">{{ formatTime(scope.row.timestamp) }}</template></el-table-column>
        <el-table-column prop="serverName" label="服务器" min-width="140" />
        <el-table-column prop="type" label="威胁类型" min-width="180" />
        <el-table-column prop="level" label="等级" width="90"><template slot-scope="scope"><el-tag :type="levelType(scope.row.level)" size="small">{{ riskText(scope.row.level) }}</el-tag></template></el-table-column>
        <el-table-column prop="remote_ip" label="目标 IP" min-width="130" />
      </el-table>
    </section>
  </div>
</template>

<script>
import * as echarts from 'echarts'
import { desktopApi, isDesktopClient } from '@/api/desktop'

const emptySummary = () => ({ riskLevel: 'safe', serverCount: 0, onlineCount: 0, cpuCandidateCount: 0, trafficAlertCount: 0, randomObservationCount: 0, alarmCount: 0, suspiciousProcesses: 0, suspiciousConnections: 0, servers: [] })

export default {
  name: 'RemoteDashboard',
  data() {
    return {
      desktop: isDesktopClient(),
      summary: emptySummary(),
      recentAlarms: [],
      selectedServerId: '',
      detecting: false,
      chart: null,
      timer: null,
      unsubscribers: []
    }
  },
  computed: {
    selectedServer() {
      return this.summary.servers.find(server => server.id === this.selectedServerId) || this.summary.servers[0]
    },
    randomObservations() {
      const latestRandom = this.selectedServer && this.selectedServer.latestRandom
      return latestRandom && Array.isArray(latestRandom.observations) ? latestRandom.observations : []
    },
    normalRandomCount() {
      return this.randomObservations.filter(row => !row.parse_error && row.result === 'normal' && !row.is_abnormal).length
    },
    abnormalRandomCount() {
      return this.randomObservations.filter(row => !row.parse_error && (row.result === 'abnormal' || row.is_abnormal)).length
    },
    randomPieTotal() { return this.normalRandomCount + this.abnormalRandomCount },
    lastDetectionTime() {
      const response = this.selectedServer && (this.selectedServer.latestRandom || this.selectedServer.latestTraffic || this.selectedServer.latestCpu)
      return response ? `最后读取：${this.formatTime(response.timestamp)}` : '尚未读取'
    }
  },
  mounted() {
    this.$nextTick(this.renderChart)
    if (!this.desktop) return
    this.refresh()
    this.timer = setInterval(this.refresh, 3000)
    this.unsubscribers.push(
      desktopApi.onDetectionResult(() => this.refresh()),
      desktopApi.onAlarm(() => this.refresh()),
      desktopApi.onRandomObservations(() => this.refresh()),
      desktopApi.onDetectionError(payload => this.$message.error(payload.message))
    )
    window.addEventListener('resize', this.resizeChart)
  },
  beforeDestroy() {
    if (this.timer) clearInterval(this.timer)
    this.unsubscribers.forEach(unsubscribe => unsubscribe())
    window.removeEventListener('resize', this.resizeChart)
    if (this.chart) this.chart.dispose()
  },
  methods: {
    async refresh() {
      try {
        const [summary, alarms] = await Promise.all([desktopApi.getSummary(), desktopApi.listAlarms({})])
        this.summary = summary || emptySummary()
        this.recentAlarms = (alarms || []).slice(0, 6)
        if (!this.selectedServerId && this.summary.servers.length) this.selectedServerId = this.summary.servers[0].id
        this.$nextTick(this.renderChart)
      } catch (error) {
        console.error(error)
      }
    },
    async runDetection(mode) {
      if (!this.desktop) return this.$message.warning('请在 MTD Windows 客户端中执行远程检测')
      if (!this.selectedServerId) return this.$message.warning('请先选择服务器')
      this.detecting = true
      try {
        await desktopApi.runDetection(this.selectedServerId, 'all')
        this.$message.success('已获取进程候选、流量告警与随机探测结果')
        await this.refresh()
      } catch (error) {
        this.$message.error(error.message || String(error))
      } finally {
        this.detecting = false
      }
    },
    renderChart() {
      if (!this.randomPieTotal) {
        if (this.chart) { this.chart.dispose(); this.chart = null }
        return
      }
      if (!this.$refs.randomPieChart) {
        this.$nextTick(this.renderChart)
        return
      }
      if (!this.chart) this.chart = echarts.init(this.$refs.randomPieChart)
      this.chart.setOption({
        color: ['#18a47f', '#d94a50'],
        tooltip: { trigger: 'item', formatter: '{b}<br/>{c} 次 ({d}%)' },
        legend: { bottom: 0, icon: 'circle', textStyle: { color: '#627386' }, data: ['正常', '异常'] },
        graphic: [{
          type: 'group',
          left: 'center',
          top: '38%',
          children: [
            { type: 'text', left: 'center', top: -18, style: { text: String(this.randomPieTotal), textAlign: 'center', fill: '#172235', fontSize: 26, fontWeight: 700 } },
            { type: 'text', left: 'center', top: 16, style: { text: '探测总数', textAlign: 'center', fill: '#7f8d9c', fontSize: 12 } }
          ]
        }],
        series: [{
          name: '随机探测',
          type: 'pie',
          radius: ['50%', '72%'],
          center: ['50%', '42%'],
          avoidLabelOverlap: true,
          label: { show: false },
          labelLine: { show: false },
          data: [
            { name: '正常', value: this.normalRandomCount },
            { name: '异常', value: this.abnormalRandomCount }
          ]
        }]
      }, true)
    },
    resizeChart() { if (this.chart) this.chart.resize() },
    riskText(level) { return ({ safe: '安全', low: '低危', medium: '中危', high: '高危', critical: '严重' })[level] || '未知' },
    statusText(level) { return ({ safe: '正常', low: '有候选', medium: '需核验', high: '高危', critical: '严重' })[level] || '未知' },
    levelType(level) { return ({ low: 'info', medium: 'warning', high: 'danger', critical: 'danger' })[level] || 'success' },
    serverRisk(server) { return this.statusText(server.riskLevel || 'safe') },
    formatTime(value) { return value ? new Date(value).toLocaleString() : '-' }
  },
  watch: {
    selectedServerId() { this.$nextTick(this.renderChart) },
    randomPieTotal() { this.$nextTick(this.renderChart) }
  }
}
</script>

<style lang="scss" scoped>
.remote-dashboard { min-height: calc(100vh - 84px); padding: 24px; background: #f1f5f8; color: #172235; }
.mode-alert { margin-bottom: 16px; }
.dashboard-hero { display: flex; align-items: center; justify-content: space-between; padding: 30px 36px; color: #fff; border-radius: 18px; background: linear-gradient(120deg, #10243d, #16445d 65%, #16716f); box-shadow: 0 18px 40px rgba(22, 57, 81, .18); }
.eyebrow, .panel-heading span { color: #5fd8cf; font-size: 11px; font-weight: 700; letter-spacing: 2px; }
.dashboard-hero h1 { margin: 10px 0 8px; font-size: 30px; }
.dashboard-hero p { margin: 0; color: #c6d7e2; }
.hero-actions { display: flex; gap: 10px; align-items: center; }
.hero-actions .el-select { width: 190px; }
.metrics { display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin: 20px 0; }
.metric-card { display: flex; align-items: center; gap: 14px; min-height: 92px; padding: 18px; border-radius: 14px; background: #fff; box-shadow: 0 8px 24px rgba(34, 62, 84, .06); }
.metric-icon { display: flex; align-items: center; justify-content: center; width: 44px; height: 44px; color: #0a8f86; font-size: 21px; border-radius: 12px; background: #def5f2; }
.metric-icon.blue { color: #3179bf; background: #e3effb; }.metric-icon.amber { color: #b47714; background: #fff0d5; }.metric-icon.violet { color: #6e58c4; background: #ede9fb; }.metric-icon.red { color: #c84c51; background: #fde8e8; }
.metric-card span { display: block; margin-bottom: 6px; color: #8290a0; font-size: 12px; }.metric-card strong { font-size: 22px; }
.risk-safe strong { color: #15978e; }.risk-low strong { color: #6280a0; }.risk-medium strong { color: #c08321; }.risk-high strong, .risk-critical strong { color: #d6454b; }
.content-grid { display: grid; grid-template-columns: minmax(0, 2fr) minmax(290px, 1fr); gap: 18px; }
.panel { padding: 24px; border-radius: 14px; background: #fff; box-shadow: 0 8px 24px rgba(34, 62, 84, .05); }
.panel-heading { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }.panel-heading span { color: #16968d; }.panel-heading h3 { margin: 6px 0 0; font-size: 17px; }.panel-heading .last-time { color: #8b98a7; font-size: 12px; letter-spacing: 0; font-weight: 400; }
.pie-layout { display: grid; grid-template-columns: minmax(0, 1fr) 160px; align-items: center; min-height: 270px; }
.random-pie-chart { height: 270px; min-width: 0; }
.pie-summary { display: grid; gap: 12px; }
.pie-summary-item { padding: 14px 16px; border-radius: 8px; background: #f6f9fb; border: 1px solid #e5edf3; }
.pie-summary-item span { display: block; color: #7f8d9c; font-size: 12px; }.pie-summary-item strong { display: block; margin-top: 5px; font-size: 25px; }.pie-summary-item.normal strong { color: #168b6f; }.pie-summary-item.abnormal strong { color: #d8464c; }
.risk-empty { height: 270px; display: flex; align-items: center; justify-content: center; }
.server-list { max-height: 270px; overflow: auto; }.server-row { display: flex; align-items: center; gap: 12px; padding: 13px 4px; cursor: pointer; border-bottom: 1px solid #edf1f4; }.server-row:last-child { border-bottom: 0; }
.status-dot { width: 9px; height: 9px; border-radius: 50%; background: #aeb8c2; }.status-dot.online, .status-dot.connected { background: #1cac82; box-shadow: 0 0 0 4px rgba(28,172,130,.12); }.status-dot.error { background: #df5157; }.status-dot.detecting { background: #e5a638; }.status-dot.disabled { background: #aeb8c2; }
.server-info { flex: 1; }.server-info strong, .server-info small { display: block; }.server-info small { margin-top: 4px; color: #8794a2; }.server-risk { color: #627386; font-size: 12px; }
.alarms-panel { margin-top: 18px; }
@media (max-width: 1200px) { .metrics { grid-template-columns: repeat(3, 1fr); }.dashboard-hero { align-items: flex-start; flex-direction: column; gap: 22px; } }
@media (max-width: 760px) { .remote-dashboard { padding: 12px; }.metrics, .content-grid, .pie-layout { grid-template-columns: 1fr; }.hero-actions { flex-wrap: wrap; }.dashboard-hero { padding: 24px; }.pie-summary { grid-template-columns: repeat(2, 1fr); } }
</style>