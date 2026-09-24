<template>
  <div class="app-container remote-random">
    <div class="page-heading">
      <div>
        <span>周期性随机探测</span>
        <h2>随机探测结果</h2>
        <p>读取远程 <code>results/random_observations/*.json</code>，展示随机短窗口探测的正常、异常与解析状态。</p>
      </div>
      <div class="heading-actions">
        <el-select v-model="selectedServerId" clearable placeholder="选择服务器" :disabled="!desktop">
          <el-option v-for="server in servers" :key="server.id" :label="server.name" :value="server.id" />
        </el-select>
        <el-button type="primary" icon="el-icon-refresh" :disabled="!desktop" :loading="reading" @click="readRandom">读取随机探测</el-button>
      </div>
    </div>

    <el-alert
      title="随机探测不是正式告警"
      description="该页面展示周期性随机探测记录，用于补充观察单个随机进程的 CPU 与挖矿协议证据；结果不会改变候选进程筛选、流量告警生成或正式风险评分。"
      type="info"
      show-icon
      :closable="false"
      class="mode-alert"
    />

    <div class="stat-row">
      <div class="stat-card"><span>探测记录</span><strong>{{ observations.length }}</strong></div>
      <div class="stat-card good"><span>正常</span><strong>{{ normalCount }}</strong></div>
      <div class="stat-card bad"><span>异常</span><strong>{{ abnormalCount }}</strong></div>
      <div class="stat-card warn"><span>解析失败</span><strong>{{ parseErrorCount }}</strong></div>
    </div>

    <el-form :inline="true" :model="filters" class="filter-form">
      <el-form-item label="服务器"><el-select v-model="filters.serverId" clearable placeholder="全部服务器"><el-option v-for="server in servers" :key="server.id" :label="server.name" :value="server.id" /></el-select></el-form-item>
      <el-form-item label="探测结果"><el-select v-model="filters.result" clearable placeholder="全部结果"><el-option label="正常" value="normal" /><el-option label="异常" value="abnormal" /><el-option label="解析失败" value="parse_error" /></el-select></el-form-item>
      <el-form-item><el-button icon="el-icon-search" @click="load">查询</el-button></el-form-item>
    </el-form>

    <el-table v-loading="loading" :data="pagedObservations" empty-text="暂无随机探测结果" @row-click="showDetail">
      <el-table-column prop="timestamp" label="生成时间" min-width="170"><template slot-scope="scope">{{ formatTime(scope.row.timestamp) }}</template></el-table-column>
      <el-table-column prop="serverName" label="服务器" min-width="110" />
      <el-table-column label="结果" width="100"><template slot-scope="scope"><el-tag :type="resultType(scope.row)" size="small">{{ resultText(scope.row) }}</el-tag></template></el-table-column>
      <el-table-column label="被探测进程" min-width="210">
        <template slot-scope="scope">
          <div class="process-cell">
            <strong>{{ scope.row.process_name || '未知进程' }}</strong>
            <small>PID {{ scope.row.pid || '-' }} / 用户 {{ scope.row.process_user || '-' }}</small>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="判定" min-width="190" show-overflow-tooltip><template slot-scope="scope">{{ verdictText(scope.row.verdict) }}</template></el-table-column>
      <el-table-column label="CPU 证据" min-width="170" show-overflow-tooltip><template slot-scope="scope">{{ computeEvidenceText(scope.row) }}</template></el-table-column>
      <el-table-column label="协议证据" min-width="210" show-overflow-tooltip><template slot-scope="scope">{{ protocolEvidenceText(scope.row) }}</template></el-table-column>
      <el-table-column label="可见性" min-width="230" show-overflow-tooltip><template slot-scope="scope">{{ visibilitySummary(scope.row) }}</template></el-table-column>
      <el-table-column label="观测时长" width="130"><template slot-scope="scope">{{ observeDurationText(scope.row) }}</template></el-table-column>
      <el-table-column prop="file_name" label="结果文件" min-width="210" show-overflow-tooltip />
    </el-table>
    <pagination v-show="observations.length > 0" :total="observations.length" :page.sync="page.pageNum" :limit.sync="page.pageSize" />

    <el-drawer title="随机探测详情" :visible.sync="drawerVisible" size="760px" append-to-body>
      <div v-if="current" class="detail-drawer">
        <div class="verdict-panel" :class="resultClass(current)">
          <span>{{ recordTypeText(current.record_type) }}</span>
          <strong>{{ resultText(current) }}：{{ current.process_name || '未知进程' }}</strong>
          <p>{{ resultDescription(current) }}</p>
        </div>

        <div class="summary-grid">
          <div class="summary-item"><span>PID</span><strong>{{ current.pid || '-' }}</strong></div>
          <div class="summary-item"><span>所属用户</span><strong>{{ current.process_user || '-' }}</strong></div>
          <div class="summary-item"><span>判定</span><strong>{{ verdictText(current.verdict) }}</strong></div>
          <div class="summary-item"><span>异常置信度</span><strong>{{ confidenceText(current.confidence) }}</strong></div>
        </div>

        <h3>本次结论</h3>
        <el-descriptions :column="1" border size="small">
          <el-descriptions-item label="服务器">{{ current.serverName }}</el-descriptions-item>
          <el-descriptions-item label="生成时间">{{ formatTime(current.timestamp) }}</el-descriptions-item>
          <el-descriptions-item label="记录类型">{{ recordTypeText(current.record_type) }}</el-descriptions-item>
          <el-descriptions-item label="探测结果">{{ resultText(current) }}</el-descriptions-item>
          <el-descriptions-item label="本次判定">{{ verdictText(current.verdict) }}</el-descriptions-item>
          <el-descriptions-item label="说明">{{ noteText(current.note) }}</el-descriptions-item>
          <el-descriptions-item label="结果文件">{{ current.sourcePath || current.source_path || '-' }}</el-descriptions-item>
          <el-descriptions-item v-if="current.parse_error" label="解析错误">{{ current.parse_error }}</el-descriptions-item>
        </el-descriptions>

        <h3>进程身份</h3>
        <el-descriptions :column="1" border size="small">
          <el-descriptions-item label="进程名称">{{ current.process_name || '-' }}</el-descriptions-item>
          <el-descriptions-item label="PID">{{ current.pid || '-' }}</el-descriptions-item>
          <el-descriptions-item label="所属用户">{{ current.process_user || '-' }}</el-descriptions-item>
          <el-descriptions-item label="可执行文件">{{ current.exe_path || '-' }}</el-descriptions-item>
          <el-descriptions-item label="执行文件 Hash">{{ current.exe_hash || '-' }}</el-descriptions-item>
          <el-descriptions-item label="命令行 Hash">{{ current.cmdline_hash || '-' }}</el-descriptions-item>
        </el-descriptions>

        <h3>证据统计</h3>
        <div class="evidence-grid">
          <div class="evidence-card">
            <span>CPU 计算证据</span>
            <strong :class="{ danger: evidenceBool(current, 'compute_evidence_present') }">{{ evidenceBool(current, 'compute_evidence_present') ? '有' : '无' }}</strong>
            <small>平均 CPU {{ percent(evidenceValue(current, 'cpu_avg_percent')) }}</small>
          </div>
          <div class="evidence-card">
            <span>挖矿协议证据</span>
            <strong>{{ protocolEvidenceText(current) }}</strong>
            <small>Job / Submit / 关联 Submit</small>
          </div>
          <div class="evidence-card">
            <span>明文 Stratum</span>
            <strong>{{ plaintextEvidenceText(current) }}</strong>
            <small>明文探针可见证据</small>
          </div>
          <div class="evidence-card">
            <span>TLS/OpenSSL</span>
            <strong>{{ tlsEvidenceText(current) }}</strong>
            <small>TLS 探针可见证据</small>
          </div>
        </div>

        <h3>探测过程</h3>
        <el-descriptions :column="1" border size="small">
          <el-descriptions-item label="配置观测时长">{{ durationValue(current.observation && current.observation.observe_duration_sec) }}</el-descriptions-item>
          <el-descriptions-item label="实际观测时长">{{ durationValue(current.observation && current.observation.actual_observe_duration_sec) }}</el-descriptions-item>
          <el-descriptions-item label="是否提前确认">{{ boolText(current.observation && current.observation.early_confirmed) }}</el-descriptions-item>
          <el-descriptions-item label="探针模式">{{ probeModeText(current.observation && current.observation.probe_mode) }}</el-descriptions-item>
          <el-descriptions-item label="明文探针">{{ enabledText(current.observation && current.observation.plaintext_probe_enabled) }}</el-descriptions-item>
          <el-descriptions-item label="TLS 探针">{{ enabledText(current.observation && current.observation.tls_probe_enabled) }}</el-descriptions-item>
          <el-descriptions-item label="是否跳过观测">{{ boolText(current.observation && current.observation.observe_skipped) }}</el-descriptions-item>
          <el-descriptions-item label="跳过原因">{{ current.observation && current.observation.skip_reason || '-' }}</el-descriptions-item>
          <el-descriptions-item label="可见性模式">{{ visibilityModeText(current.visibility_mode) }}</el-descriptions-item>
          <el-descriptions-item label="可见性边界">{{ visibilityBoundaryText(current.visibility_boundary) }}</el-descriptions-item>
        </el-descriptions>

        <h3>判定原因</h3>
        <div class="reason-tags">
          <el-tag v-for="reason in reasonItems(current)" :key="reason" size="small" type="info">{{ reasonText(reason) }}</el-tag>
          <span v-if="!reasonItems(current).length" class="empty-text">无额外原因</span>
        </div>

        <h3>隐私保护</h3>
        <div class="privacy-grid">
          <div v-for="item in privacyItems(current)" :key="item.key" :class="['privacy-item', { saved: item.saved }]">
            <span>{{ item.label }}</span>
            <strong>{{ item.saved ? '已保存' : '未保存' }}</strong>
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

const VERDICT_TEXT = {
  benign_or_unconfirmed: '良性或未确认异常',
  abnormal: '异常',
  suspicious: '需核验',
  confirmed: '已确认异常',
  mining_confirmed: '已确认挖矿',
  normal: '正常'
}

const RECORD_TYPE_TEXT = {
  periodic_random_observation: '周期性随机探测',
  random_observation: '随机探测记录'
}

const CONFIDENCE_TEXT = {
  none: '无异常置信度',
  low: '低',
  medium: '中',
  high: '高',
  critical: '严重'
}

const NOTE_TEXT = {
  'Periodic random probe; does not change formal alert policy.': '周期性随机探测；不改变正式告警策略。'
}

const PRIVACY_LABELS = {
  raw_payload_saved: '原始流量',
  wallet_saved: '钱包地址',
  job_id_saved: 'Job ID',
  nonce_saved: 'Nonce',
  result_saved: 'Result',
  blob_saved: 'Blob',
  full_cmdline_saved: '完整命令行'
}

export default {
  name: 'RemoteRandomObservations',
  data() {
    return {
      desktop: isDesktopClient(), loading: false, reading: false, servers: [], observations: [], selectedServerId: '',
      filters: { serverId: '', result: '' }, page: { pageNum: 1, pageSize: 10 }, drawerVisible: false, current: null, unsubscribe: null
    }
  },
  computed: {
    pagedObservations() { const start = (this.page.pageNum - 1) * this.page.pageSize; return this.observations.slice(start, start + this.page.pageSize) },
    normalCount() { return this.observations.filter(row => !row.parse_error && row.result === 'normal' && !row.is_abnormal).length },
    abnormalCount() { return this.observations.filter(row => !row.parse_error && (row.result === 'abnormal' || row.is_abnormal)).length },
    parseErrorCount() { return this.observations.filter(row => row.parse_error).length },
    formattedCurrent() { return JSON.stringify(this.current && this.current.raw || this.current || {}, null, 2) }
  },
  created() {
    if (!this.desktop) return
    this.loadServers(); this.load()
    this.unsubscribe = desktopApi.onRandomObservations(() => this.load())
  },
  beforeDestroy() { if (this.unsubscribe) this.unsubscribe() },
  methods: {
    async loadServers() { this.servers = await desktopApi.listServers() },
    async load() {
      this.loading = true
      try { this.observations = await desktopApi.listRandomObservations(this.filters); this.page.pageNum = 1 }
      catch (error) { this.$message.error(error.message || String(error)) }
      finally { this.loading = false }
    },
    async readRandom() {
      if (!this.selectedServerId) return this.$message.warning('请先选择服务器')
      this.reading = true
      try {
        await desktopApi.readRandomObservations(this.selectedServerId)
        this.$message.success('随机探测结果已读取')
        if (!this.filters.serverId) this.filters.serverId = this.selectedServerId
        await this.load()
      } catch (error) {
        this.$message.error(error.message || String(error))
      } finally {
        this.reading = false
      }
    },
    showDetail(row) { this.current = row; this.drawerVisible = true },
    resultText(row) {
      if (row.parse_error) return '解析失败'
      if (row.result === 'abnormal' || row.is_abnormal) return '异常'
      if (row.result === 'normal') return '正常'
      return '未知'
    },
    resultType(row) {
      if (row.parse_error) return 'warning'
      if (row.result === 'abnormal' || row.is_abnormal) return 'danger'
      if (row.result === 'normal') return 'success'
      return 'info'
    },
    resultClass(row) {
      if (row.parse_error) return 'parse-error'
      return row.result === 'abnormal' || row.is_abnormal ? 'abnormal' : 'normal'
    },
    resultDescription(row) {
      if (row.parse_error) return '该结果文件未能解析，请检查 JSON 格式或文件内容。'
      if (row.result === 'abnormal' || row.is_abnormal) return '本次随机短窗口探测出现异常信号；它仍是补充观察记录，不会直接改写正式告警规则。'
      return '本次周期性随机探测没有发现挖矿协议证据或 CPU 计算证据，不是正式告警。'
    },
    recordTypeText(value) { return RECORD_TYPE_TEXT[value] || value || '随机探测记录' },
    verdictText(value) { return VERDICT_TEXT[value] || value || '-' },
    confidenceText(value) { return CONFIDENCE_TEXT[value] || value || '-' },
    noteText(value) { return NOTE_TEXT[value] || value || '不影响正式告警策略' },
    evidenceValue(row, key) { return row && row.evidence && row.evidence[key] !== undefined ? row.evidence[key] : 0 },
    evidenceBool(row, key) { return this.evidenceValue(row, key) === true },
    computeEvidenceText(row) {
      const prefix = this.evidenceBool(row, 'compute_evidence_present') ? '有计算证据' : '无计算证据'
      return `${prefix}，平均 CPU ${this.percent(this.evidenceValue(row, 'cpu_avg_percent'))}`
    },
    protocolEvidenceText(row) {
      return `Job ${this.count(row, 'job_marker_count')} / Submit ${this.count(row, 'submit_marker_count')} / 关联 ${this.count(row, 'associated_submit_count')}`
    },
    plaintextEvidenceText(row) {
      return `Job ${this.count(row, 'plaintext_job_marker_count')} / Submit ${this.count(row, 'plaintext_submit_marker_count')} / 关联 ${this.count(row, 'plaintext_associated_submit_count')}`
    },
    tlsEvidenceText(row) {
      return `Job ${this.count(row, 'tls_job_marker_count')} / Submit ${this.count(row, 'tls_submit_marker_count')} / 关联 ${this.count(row, 'tls_associated_submit_count')}`
    },
    count(row, key) {
      const number = Number(this.evidenceValue(row, key))
      return Number.isFinite(number) ? number : 0
    },
    percent(value) {
      const number = Number(value)
      if (!Number.isFinite(number)) return '-'
      return `${number.toFixed(Number.isInteger(number) ? 0 : 1)}%`
    },
    observeDurationText(row) {
      const actual = row && row.observation && row.observation.actual_observe_duration_sec
      const configured = row && row.observation && row.observation.observe_duration_sec
      return actual !== undefined && actual !== null && actual !== '' ? this.durationValue(actual) : this.durationValue(configured)
    },
    durationValue(value) {
      const number = Number(value)
      if (!Number.isFinite(number)) return '-'
      return `${number.toFixed(Number.isInteger(number) ? 0 : 1)} 秒`
    },
    visibilitySummary(row) {
      if (row.parse_error) return '-'
      if (row.visibility_boundary) return this.visibilityBoundaryText(row.visibility_boundary)
      return this.visibilityModeText(row.visibility_mode)
    },
    visibilityModeText(value) {
      return ({ none: '未看到明文 Stratum 或 TLS/OpenSSL 挖矿标记', plaintext: '明文探针可见', tls: 'TLS/OpenSSL 探针可见', both: '明文与 TLS 探针均可见' })[value] || value || '-'
    },
    visibilityBoundaryText(value) {
      return ({ no_dynamic_libssl_mapping: '目标进程没有动态 libssl 映射，TLS/OpenSSL 探针未启用或不可见' })[value] || value || '-'
    },
    probeModeText(value) { return ({ on_demand: '按需探针', periodic: '周期探针' })[value] || value || '-' },
    boolText(value) { return value === true ? '是' : value === false ? '否' : '-' },
    enabledText(value) { return value === true ? '已启用' : value === false ? '未启用' : '-' },
    reasonItems(row) { return Array.isArray(row && row.reasons) ? row.reasons : [] },
    reasonText(value) {
      return ({ 'visibility_boundary:no_dynamic_libssl_mapping': '可见性边界：目标进程没有动态 libssl 映射' })[value] || value
    },
    privacyItems(row) {
      const privacy = row && row.privacy && typeof row.privacy === 'object' ? row.privacy : {}
      const keys = Object.keys(privacy).length ? Object.keys(privacy) : Object.keys(PRIVACY_LABELS)
      return keys.map(key => ({ key, label: PRIVACY_LABELS[key] || key, saved: privacy[key] === true }))
    },
    formatTime(value) { return value ? new Date(value).toLocaleString() : '-' }
  }
}
</script>

<style lang="scss" scoped>
.remote-random { min-height:calc(100vh - 84px); background:#f4f7fa; }
.page-heading { display:flex; align-items:center; justify-content:space-between; gap:18px; margin-bottom:16px; padding:26px 30px; color:#fff; border-radius:16px; background:linear-gradient(120deg,#1f334a,#20645f); }
.page-heading span { color:#7ee0d1; font-size:11px; font-weight:700; letter-spacing:2px; }.page-heading h2 { margin:7px 0; }.page-heading p { margin:0; color:#d6e4e8; }.page-heading code { color:#d6fff8; background:rgba(255,255,255,.12); border-radius:4px; padding:2px 5px; }
.heading-actions { display:flex; align-items:center; gap:10px; }.heading-actions .el-select { width:190px; }
.mode-alert { margin-bottom:14px; }
.stat-row { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:14px; }
.stat-card { padding:18px 20px; border-radius:8px; background:#fff; box-shadow:0 8px 22px rgba(34, 62, 84, .05); }.stat-card span { display:block; color:#8493a3; font-size:12px; }.stat-card strong { display:block; margin-top:7px; color:#273c52; font-size:24px; }
.stat-card.good strong { color:#168b6f; }.stat-card.bad strong { color:#d8464c; }.stat-card.warn strong { color:#c17a18; }
.filter-form { padding:14px 18px 0; margin-bottom:14px; border-radius:12px; background:#fff; }
.process-cell strong,.process-cell small { display:block; }.process-cell strong { color:#34485b; }.process-cell small { margin-top:3px; color:#8b98a7; font-size:12px; }
.detail-drawer { padding:0 24px 30px; }.detail-drawer h3 { margin:24px 0 10px; font-size:15px; color:#263b50; }
.verdict-panel { margin-bottom:16px; padding:18px; border-left:4px solid #2c9a7f; border-radius:8px; background:#effbf7; }.verdict-panel.abnormal { border-left-color:#d8464c; background:#fff3f3; }.verdict-panel.parse-error { border-left-color:#d6922b; background:#fff8ea; }
.verdict-panel span,.verdict-panel strong { display:block; }.verdict-panel span { color:#718294; font-size:12px; }.verdict-panel strong { margin-top:5px; color:#263b50; font-size:22px; }.verdict-panel p { margin:8px 0 0; color:#68798a; line-height:1.6; }
.summary-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-bottom:18px; }.summary-item,.evidence-card,.privacy-item { padding:12px; border:1px solid #e2e9f0; border-radius:8px; background:#fff; }.summary-item span,.summary-item strong,.evidence-card span,.evidence-card strong,.evidence-card small,.privacy-item span,.privacy-item strong { display:block; }
.summary-item span,.evidence-card span,.privacy-item span { color:#7f8d9c; font-size:12px; }.summary-item strong { margin-top:5px; color:#263b50; font-size:15px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.evidence-grid { display:grid; grid-template-columns:repeat(2,1fr); gap:10px; }.evidence-card strong { margin-top:6px; color:#273c52; font-size:16px; }.evidence-card strong.danger { color:#d8464c; }.evidence-card small { margin-top:5px; color:#8b98a7; }
.reason-tags { display:flex; flex-wrap:wrap; gap:6px; }.empty-text { color:#8b98a7; font-size:13px; }
.privacy-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; }.privacy-item strong { margin-top:5px; color:#168b6f; }.privacy-item.saved strong { color:#d8464c; }
.json-report { max-height:360px; padding:14px; overflow:auto; color:#cbd8e5; font-size:12px; line-height:1.6; border-radius:10px; background:#132337; }
@media (max-width: 1080px) { .summary-grid,.privacy-grid { grid-template-columns:repeat(2,1fr); } }
@media (max-width: 980px) { .stat-row,.evidence-grid { grid-template-columns:repeat(2,1fr); } }
@media (max-width: 760px) { .page-heading { align-items:flex-start; flex-direction:column; }.heading-actions { width:100%; flex-wrap:wrap; }.stat-row,.summary-grid,.evidence-grid,.privacy-grid { grid-template-columns:1fr; } }
</style>