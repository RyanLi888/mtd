<template>
  <div class="app-container remote-alarms">
    <div class="page-heading">
      <div><span>TRAFFIC ALERTS</span><h2>流量告警</h2><p>读取远程流量告警文件，查看告警连接与远端地址。</p></div>
      <div class="heading-actions">
        <el-select v-model="selectedServerId" clearable placeholder="选择服务器" :disabled="!desktop">
          <el-option v-for="server in servers" :key="server.id" :label="server.name" :value="server.id" />
        </el-select>
        <el-button type="primary" icon="el-icon-refresh" :disabled="!desktop" :loading="reading" @click="readTraffic">读取流量告警</el-button>
      </div>
    </div>

    <el-form :inline="true" :model="filters" class="filter-form">
      <el-form-item label="服务器"><el-select v-model="filters.serverId" clearable placeholder="全部服务器"><el-option v-for="server in servers" :key="server.id" :label="server.name" :value="server.id" /></el-select></el-form-item>
      <el-form-item label="风险等级"><el-select v-model="filters.level" clearable placeholder="全部等级"><el-option label="严重" value="critical" /><el-option label="高危" value="high" /><el-option label="中危" value="medium" /><el-option label="低危" value="low" /></el-select></el-form-item>
      <el-form-item><el-button icon="el-icon-search" @click="load">查询</el-button></el-form-item>
    </el-form>

    <el-table v-loading="loading" :data="pagedAlerts" empty-text="暂无流量告警" @row-click="showDetail">
      <el-table-column prop="timestamp" label="时间" min-width="170"><template slot-scope="scope">{{ formatTime(scope.row.timestamp) }}</template></el-table-column>
      <el-table-column prop="serverName" label="服务器" min-width="130" />
      <el-table-column prop="source_ip" label="源 IP" min-width="130" />
      <el-table-column prop="remote_ip" label="目标 IP" min-width="130" />
      <el-table-column prop="remote_port" label="端口" width="85" />
      <el-table-column prop="protocol" label="协议" width="80" />
      <el-table-column prop="process" label="进程" min-width="130" />
      <el-table-column prop="level" label="等级" width="90"><template slot-scope="scope"><el-tag :type="levelType(scope.row.level)" size="small">{{ riskText(scope.row.level) }}</el-tag></template></el-table-column>
      <el-table-column label="操作" width="100"><template slot-scope="scope"><el-button type="text" class="danger" @click.stop="confirmRemediation(scope.row)">封禁 IP</el-button></template></el-table-column>
    </el-table>
    <pagination v-show="alerts.length > 0" :total="alerts.length" :page.sync="page.pageNum" :limit.sync="page.pageSize" />

    <el-drawer title="流量告警详情" :visible.sync="drawerVisible" size="620px" append-to-body>
      <div v-if="current" class="report-drawer">
        <el-descriptions :column="1" border size="small">
          <el-descriptions-item label="服务器">{{ current.serverName }}</el-descriptions-item>
          <el-descriptions-item label="告警时间">{{ formatTime(current.timestamp) }}</el-descriptions-item>
          <el-descriptions-item label="源 IP">{{ current.source_ip || '-' }}</el-descriptions-item>
          <el-descriptions-item label="目标 IP">{{ current.remote_ip || '-' }}</el-descriptions-item>
          <el-descriptions-item label="目标端口">{{ current.remote_port || '-' }}</el-descriptions-item>
          <el-descriptions-item label="进程">{{ current.process || '-' }}</el-descriptions-item>
          <el-descriptions-item label="结果文件">{{ current.sourcePath }}</el-descriptions-item>
        </el-descriptions>
        <h3>原始 JSON</h3>
        <pre class="json-report">{{ formattedCurrent }}</pre>
      </div>
    </el-drawer>
  </div>
</template>

<script>
import { desktopApi, isDesktopClient } from '@/api/desktop'

export default {
  name: 'RemoteAlarms',
  data() {
    return { desktop: isDesktopClient(), loading: false, reading: false, servers: [], alerts: [], selectedServerId: '', filters: { serverId: '', level: '' }, page: { pageNum: 1, pageSize: 10 }, drawerVisible: false, current: null, unsubscribe: null }
  },
  computed: {
    pagedAlerts() { const start = (this.page.pageNum - 1) * this.page.pageSize; return this.alerts.slice(start, start + this.page.pageSize) },
    formattedCurrent() { return JSON.stringify(this.current && this.current.raw || this.current || {}, null, 2) }
  },
  created() {
    if (!this.desktop) return
    this.loadServers(); this.load()
    this.unsubscribe = desktopApi.onTrafficAlerts(() => this.load())
  },
  beforeDestroy() { if (this.unsubscribe) this.unsubscribe() },
  methods: {
    async loadServers() { this.servers = await desktopApi.listServers() },
    async load() { this.loading = true; try { this.alerts = await desktopApi.listTrafficAlerts(this.filters); this.page.pageNum = 1 } catch (error) { this.$message.error(error.message || String(error)) } finally { this.loading = false } },
    async readTraffic() {
      if (!this.selectedServerId) return this.$message.warning('请先选择服务器')
      this.reading = true
      try {
        await desktopApi.readTrafficAlerts(this.selectedServerId)
        this.$message.success('流量告警已读取')
        if (!this.filters.serverId) this.filters.serverId = this.selectedServerId
        await this.load()
      } catch (error) {
        this.$message.error(error.message || String(error))
      } finally {
        this.reading = false
      }
    },
    showDetail(row) { this.current = row; this.drawerVisible = true },
    confirmRemediation(row) {
      const target = row.remote_ip
      if (!target) return this.$message.warning('该告警缺少目标 IP')
      this.$confirm(`封禁 IP ${target} 将修改远程服务器状态。确认继续吗？`, '高风险操作确认', { confirmButtonText: '确认执行', cancelButtonText: '取消', type: 'warning', closeOnClickModal: false }).then(async () => {
        try { await desktopApi.remediate({ serverId: row.serverId, action: 'block_ip', target, confirmed: true }); this.$message.success('封禁 IP 执行成功') }
        catch (error) { this.$message.error(error.message || String(error)) }
      }).catch(() => {})
    },
    riskText(level) { return ({ low: '低危', medium: '中危', high: '高危', critical: '严重', safe: '安全', unknown: '未知' })[level] || level },
    levelType(level) { return ({ low: 'info', medium: 'warning', high: 'danger', critical: 'danger' })[level] || 'success' },
    formatTime(value) { return value ? new Date(value).toLocaleString() : '-' }
  }
}
</script>

<style lang="scss" scoped>
.remote-alarms { min-height:calc(100vh - 84px); background:#f4f7fa; }
.page-heading { display:flex; align-items:center; justify-content:space-between; gap:18px; margin-bottom:18px; padding:26px 30px; color:#fff; border-radius:16px; background:linear-gradient(120deg,#182b46,#704b57); }
.page-heading span { color:#f0b5b8; font-size:11px; font-weight:700; letter-spacing:2px; }.page-heading h2 { margin:7px 0; }.page-heading p { margin:0; color:#d9d2d8; }
.heading-actions { display:flex; align-items:center; gap:10px; }.heading-actions .el-select { width:190px; }
.filter-form { padding:14px 18px 0; border-radius:12px; background:#fff; }.report-drawer { padding:0 24px 30px; }.report-drawer h3 { margin:24px 0 10px; font-size:15px; }.danger { color:#d8464c; }.json-report { max-height:360px; padding:14px; overflow:auto; color:#cbd8e5; font-size:12px; line-height:1.6; border-radius:10px; background:#132337; }
@media (max-width: 760px) { .page-heading { align-items:flex-start; flex-direction:column; }.heading-actions { width:100%; flex-wrap:wrap; } }
</style>