<template>
  <div class="app-container remote-process">
    <div class="page-heading">
      <div>
        <span>PROCESS CANDIDATES</span>
        <h2>进程监测</h2>
        <p>展示候选进程状态，按挖矿相关信号区分一般候选、需核验和强信号候选。</p>
      </div>
      <div class="heading-actions">
        <el-select v-model="selectedServerId" clearable placeholder="选择服务器" :disabled="!desktop">
          <el-option v-for="server in servers" :key="server.id" :label="server.name" :value="server.id" />
        </el-select>
        <el-button type="primary" icon="el-icon-refresh" :disabled="!desktop" :loading="reading" @click="readProcessCandidates">读取候选进程</el-button>
      </div>
    </div>

    <el-alert v-if="!desktop" title="请在 MTD Windows 客户端中读取进程候选状态" type="warning" show-icon :closable="false" />

    <div class="stat-row">
      <div class="stat-card"><span>候选进程</span><strong>{{ candidates.length }}</strong></div>
      <div class="stat-card strong"><span>强信号</span><strong>{{ strongCount }}</strong></div>
      <div class="stat-card warning"><span>包含高 CPU</span><strong>{{ highCpuCount }}</strong></div>
      <div class="stat-card muted"><span>一般候选</span><strong>{{ weakCount }}</strong></div>
    </div>

    <div class="tool-row">
      <el-radio-group v-model="levelFilter" size="small" @change="page.pageNum = 1">
        <el-radio-button label="all">全部</el-radio-button>
        <el-radio-button label="high">强信号</el-radio-button>
        <el-radio-button label="medium">需核验</el-radio-button>
        <el-radio-button label="low">一般候选</el-radio-button>
      </el-radio-group>
      <el-select v-model="reasonFilter" clearable size="small" placeholder="命中信号" @change="page.pageNum = 1">
        <el-option v-for="reason in reasonOptions" :key="reason.value" :label="reason.label" :value="reason.value" />
      </el-select>
      <span class="source-hint">最终告警以 <code>results/alerts.jsonl</code> 和 <code>results/observations/</code> 为准</span>
    </div>

    <el-table v-loading="loading" :data="pagedCandidates" class="candidate-table" empty-text="暂无进程候选" @row-click="showDetail">
      <el-table-column label="研判" width="110">
        <template slot-scope="scope"><el-tag :type="levelType(candidateLevel(scope.row))" size="small">{{ levelText(candidateLevel(scope.row)) }}</el-tag></template>
      </el-table-column>
      <el-table-column label="进程创建时间" min-width="175"><template slot-scope="scope">{{ processCreateTime(scope.row) }}</template></el-table-column>
      <el-table-column prop="serverName" label="服务器" min-width="120" />
      <el-table-column label="进程" min-width="190">
        <template slot-scope="scope">
          <div class="process-cell"><strong>{{ scope.row.name }}</strong><small>PID {{ scope.row.pid || '-' }}</small></div>
        </template>
      </el-table-column>
      <el-table-column prop="hit_count" label="命中" width="80" />
      <el-table-column prop="exe_hash" label="执行文件 Hash" min-width="180" show-overflow-tooltip><template slot-scope="scope">{{ shortHash(scope.row.exe_hash) }}</template></el-table-column>
      <el-table-column label="命中信号" min-width="300">
        <template slot-scope="scope"><div class="reason-tags"><el-tag v-for="reason in normalizedReasons(scope.row)" :key="reason.value" :type="reason.type" size="mini">{{ reason.label }}</el-tag></div></template>
      </el-table-column>
      <el-table-column label="操作" width="110">
        <template slot-scope="scope"><el-button type="text" class="danger" @click.stop="confirmRemediation(scope.row)">终止进程</el-button></template>
      </el-table-column>
    </el-table>
    <pagination v-show="filteredCandidates.length > 0" :total="filteredCandidates.length" :page.sync="page.pageNum" :limit.sync="page.pageSize" />

    <el-drawer title="候选进程详情" :visible.sync="drawerVisible" size="680px" append-to-body>
      <div v-if="current" class="detail-drawer">
        <div class="verdict-panel" :class="candidateLevel(current)">
          <span>{{ levelText(candidateLevel(current)) }}</span>
          <strong>{{ current.name }}</strong>
          <p>{{ verdictText(current) }}</p>
        </div>
        <el-descriptions :column="1" border size="small">
          <el-descriptions-item label="服务器">{{ current.serverName }}</el-descriptions-item>
          <el-descriptions-item label="PID">{{ current.pid || '-' }}</el-descriptions-item>
          <el-descriptions-item label="进程名">{{ current.name }}</el-descriptions-item>
          <el-descriptions-item label="命中次数">{{ current.hit_count || 0 }}</el-descriptions-item>
          <el-descriptions-item label="进程创建时间">{{ processCreateTime(current) }}</el-descriptions-item>
          <el-descriptions-item label="首次发现">{{ formatTime(current.first_seen) }}</el-descriptions-item>
          <el-descriptions-item label="最后发现">{{ formatTime(current.last_seen || current.timestamp) }}</el-descriptions-item>
          <el-descriptions-item label="候选文件">{{ current.sourcePath }}</el-descriptions-item>
        </el-descriptions>
        <h3>命中信号</h3>
        <div class="reason-tags detail-tags"><el-tag v-for="reason in normalizedReasons(current)" :key="reason.value" :type="reason.type" size="small">{{ reason.label }}</el-tag></div>
        <div class="signal-grid">
          <div v-for="item in signalCards" :key="item.key" :class="['signal-item', { active: hasReason(current, item.key) }]">
            <span>{{ item.label }}</span><strong>{{ hasReason(current, item.key) ? '命中' : '未命中' }}</strong>
          </div>
        </div>
        <h3>原始 JSON</h3>
        <pre class="json-report">{{ formattedCurrent }}</pre>
      </div>
    </el-drawer>
  </div>
</template>

<script>
import { desktopApi, isDesktopClient } from '@/api/desktop'

const REASON_META = {
  high_cpu: { label: '高 CPU', type: 'danger', weight: 4 },
  name_suspicious: { label: '矿工名特征', type: 'danger', weight: 4 },
  has_libssl: { label: 'TLS/libssl', type: 'warning', weight: 2 },
  network_activity: { label: '网络活动', type: 'info', weight: 1 },
  not_whitelisted: { label: '未白名单', type: 'info', weight: 1 },
  runtime_ok: { label: '运行时长达标', type: '', weight: 1 }
}

export default {
  name: 'RemoteProcess',
  data() {
    return {
      desktop: isDesktopClient(), loading: false, reading: false, servers: [], selectedServerId: '', candidates: [],
      levelFilter: 'all', reasonFilter: '', page: { pageNum: 1, pageSize: 10 }, lastReadTime: '', drawerVisible: false, current: null, unsubscribe: null,
      signalCards: [
        { key: 'high_cpu', label: 'CPU 达阈值' },
        { key: 'name_suspicious', label: '矿工命名特征' },
        { key: 'has_libssl', label: 'TLS 通信库' },
        { key: 'network_activity', label: '网络连接' },
        { key: 'not_whitelisted', label: '不在白名单' },
        { key: 'runtime_ok', label: '运行时间达标' }
      ]
    }
  },
  computed: {
    reasonOptions() { return Object.keys(REASON_META).map(value => ({ value, label: REASON_META[value].label })) },
    filteredCandidates() {
      return this.candidates.filter(row => {
        const level = this.candidateLevel(row)
        if (this.levelFilter !== 'all' && level !== this.levelFilter) return false
        if (this.reasonFilter && !this.hasReason(row, this.reasonFilter)) return false
        return true
      })
    },
    pagedCandidates() { const start = (this.page.pageNum - 1) * this.page.pageSize; return this.filteredCandidates.slice(start, start + this.page.pageSize) },
    strongCount() { return this.candidates.filter(row => this.candidateLevel(row) === 'high').length },
    highCpuCount() { return this.candidates.filter(row => this.hasReason(row, 'high_cpu')).length },
    weakCount() { return this.candidates.filter(row => this.candidateLevel(row) === 'low').length },
    formattedCurrent() { return JSON.stringify(this.current && this.current.raw || this.current || {}, null, 2) }
  },
  created() {
    if (!this.desktop) return
    this.loadServers().then(() => this.load())
    this.unsubscribe = desktopApi.onCpuResult(() => this.load())
  },
  beforeDestroy() { if (this.unsubscribe) this.unsubscribe() },
  methods: {
    async loadServers() { this.servers = await desktopApi.listServers() },
    async load() {
      this.loading = true
      try { this.candidates = await desktopApi.listCpuCandidates({ serverId: this.selectedServerId }); this.page.pageNum = 1 }
      catch (error) { this.$message.error(error.message || String(error)) }
      finally { this.loading = false }
    },
    async readProcessCandidates() {
      if (!this.selectedServerId) return this.$message.warning('请先选择服务器')
      this.reading = true
      try {
        await desktopApi.readCpuResult(this.selectedServerId)
        this.lastReadTime = new Date().toISOString()
        this.$message.success('进程候选状态已读取')
        await this.load()
      } catch (error) {
        this.$message.error(error.message || String(error))
      } finally {
        this.reading = false
      }
    },
    reasons(row) { return Array.isArray(row.last_reasons) ? row.last_reasons : [] },
    hasReason(row, reason) { return this.reasons(row).includes(reason) },
    normalizedReasons(row) {
      return this.reasons(row).map(value => ({ value, ...(REASON_META[value] || { label: value, type: '', weight: 1 }) }))
    },
    candidateLevel(row) {
      const hitCount = Number(row.hit_count || 0)
      if (this.hasReason(row, 'name_suspicious') || (this.hasReason(row, 'high_cpu') && this.hasReason(row, 'has_libssl'))) return 'high'
      if (this.hasReason(row, 'high_cpu') || hitCount >= 3) return 'medium'
      return 'low'
    },
    levelText(level) { return ({ high: '强信号', medium: '需核验', low: '一般候选' })[level] || '候选' },
    levelType(level) { return ({ high: 'danger', medium: 'warning', low: 'info' })[level] || 'info' },
    verdictText(row) {
      const level = this.candidateLevel(row)
      if (level === 'high') return '出现高 CPU、矿工命名或多次命中等强信号，仍需结合流量告警和观测结果确认。'
      if (level === 'medium') return '包含高 CPU 或重复命中等信号，建议继续核验进程来源和网络目的地。'
      return '当前主要是网络活动、未白名单、运行时长达标等候选信号，不能单独作为挖矿结论。'
    },
    shortHash(value) { return value && value.length > 22 ? `${value.slice(0, 22)}...` : value || '-' },
    showDetail(row) { this.current = row; this.drawerVisible = true },
    confirmRemediation(row) {
      if (!row.pid) return this.$message.warning('该候选进程缺少 PID')
      this.$confirm(`终止进程 ${row.pid} 将修改远程服务器状态。确认继续吗？`, '高风险操作确认', { confirmButtonText: '确认执行', cancelButtonText: '取消', type: 'warning', closeOnClickModal: false }).then(async () => {
        try { await desktopApi.remediate({ serverId: row.serverId, action: 'kill_process', target: String(row.pid), confirmed: true }); this.$message.success('终止进程执行成功') }
        catch (error) { this.$message.error(error.message || String(error)) }
      }).catch(() => {})
    },
    processCreateTime(row) {
      if (!row) return '-'
      return this.formatTime(row.create_time_iso || this.epochToIso(row.create_time))
    },
    epochToIso(value) {
      const number = Number(value)
      return Number.isFinite(number) && number > 0 ? new Date(number * 1000).toISOString() : ''
    },
    formatTime(value) { return value ? new Date(value).toLocaleString() : '-' }
  },
  watch: {
    selectedServerId() { this.load() }
  }
}
</script>

<style lang="scss" scoped>
.remote-process { min-height:calc(100vh - 84px); background:#f4f7fa; }
.page-heading { display:flex; align-items:center; justify-content:space-between; gap:18px; margin-bottom:18px; padding:26px 30px; color:#fff; border-radius:12px; background:#183a4f; }
.page-heading span { color:#78d7c6; font-size:11px; font-weight:700; letter-spacing:2px; }.page-heading h2 { margin:7px 0; }.page-heading p { margin:0; color:#d5e4ec; }
.heading-actions { display:flex; align-items:center; gap:10px; }.heading-actions .el-select { width:190px; }
.stat-row { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:14px; }
.stat-card { padding:18px 20px; border-radius:8px; background:#fff; box-shadow:0 8px 22px rgba(34, 62, 84, .05); }.stat-card span { display:block; color:#8493a3; font-size:12px; }.stat-card strong { display:block; margin-top:7px; color:#273c52; font-size:24px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.stat-card.strong strong { color:#d94a50; }.stat-card.warning strong { color:#bf7b17; }.stat-card.muted strong { color:#607389; }
.tool-row { display:flex; align-items:center; gap:12px; margin-bottom:14px; padding:12px 14px; border-radius:8px; background:#fff; }
.tool-row .el-select { width:160px; }.source-hint { margin-left:auto; color:#7f8d9c; font-size:12px; }.source-hint code { color:#42566b; background:#f1f5f8; border-radius:4px; padding:2px 5px; }
.candidate-table { border-radius:8px; overflow:hidden; }.process-cell strong,.process-cell small { display:block; }.process-cell strong { color:#34485b; }.process-cell small { margin-top:3px; color:#8b98a7; font-size:12px; }
.reason-tags { display:flex; flex-wrap:wrap; gap:6px; }.danger { color:#d8464c; }
.detail-drawer { padding:0 24px 30px; }.detail-drawer h3 { margin:22px 0 10px; font-size:15px; }.detail-tags { margin-bottom:14px; }
.verdict-panel { margin-bottom:16px; padding:18px; border-left:4px solid #8ba0b3; border-radius:8px; background:#f4f7fa; }.verdict-panel span,.verdict-panel strong { display:block; }.verdict-panel span { color:#718294; font-size:12px; }.verdict-panel strong { margin-top:5px; color:#263b50; font-size:22px; }.verdict-panel p { margin:8px 0 0; color:#68798a; line-height:1.6; }.verdict-panel.high { border-left-color:#d8464c; background:#fff3f3; }.verdict-panel.medium { border-left-color:#d6922b; background:#fff8ea; }.verdict-panel.low { border-left-color:#7a9ab9; }
.signal-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:10px; margin-top:12px; }.signal-item { padding:12px; border:1px solid #e2e9f0; border-radius:8px; background:#fff; }.signal-item span,.signal-item strong { display:block; }.signal-item span { color:#7f8d9c; font-size:12px; }.signal-item strong { margin-top:5px; color:#99a6b3; }.signal-item.active { border-color:#b7d8cf; background:#f2fbf8; }.signal-item.active strong { color:#1b8b74; }
.json-report { max-height:340px; padding:14px; overflow:auto; color:#cbd8e5; font-size:12px; line-height:1.6; border-radius:8px; background:#132337; }
@media (max-width: 980px) { .stat-row,.signal-grid { grid-template-columns:repeat(2,1fr); }.tool-row { flex-wrap:wrap; }.source-hint { margin-left:0; width:100%; } }
@media (max-width: 760px) { .page-heading { align-items:flex-start; flex-direction:column; }.heading-actions { width:100%; flex-wrap:wrap; }.stat-row,.signal-grid { grid-template-columns:1fr; } }
</style>