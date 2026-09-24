<template>
  <div class="app-container remote-servers">
    <div class="page-heading">
      <div><span>SSH TARGETS</span><h2>远程服务器管理</h2><p>管理检测代理所在的 Linux 服务器及 SSH 认证信息。</p></div>
      <el-button type="primary" icon="el-icon-plus" :disabled="!desktop" @click="openCreate">添加服务器</el-button>
    </div>

    <el-alert v-if="!desktop" title="请在 MTD Windows 客户端中管理 SSH 服务器" type="warning" show-icon :closable="false" />

    <el-table v-loading="loading" :data="servers" class="server-table" empty-text="暂无服务器配置">
      <el-table-column label="状态" width="90" align="center">
        <template slot-scope="scope"><span class="status-pill" :class="statusOf(scope.row)">{{ statusText(statusOf(scope.row)) }}</span></template>
      </el-table-column>
      <el-table-column prop="name" label="名称" min-width="150" />
      <el-table-column label="SSH 地址" min-width="170"><template slot-scope="scope">{{ scope.row.host }}:{{ scope.row.port }}</template></el-table-column>
      <el-table-column prop="username" label="用户" width="120" />
      <el-table-column label="项目与结果文件" min-width="360">
        <template slot-scope="scope">
          <div class="path-cell">
            <strong>{{ scope.row.projectPath }}</strong>
            <small>进程：{{ scope.row.cpuResultPath }}</small>
            <small>流量：{{ scope.row.trafficAlertPath }}</small>
            <small>随机探测：{{ scope.row.randomObservationPath }}</small>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="认证" width="100"><template slot-scope="scope">{{ scope.row.authType === 'key' ? '密钥' : '密码' }}</template></el-table-column>
      <el-table-column label="检测间隔" width="105"><template slot-scope="scope">{{ scope.row.checkInterval }} 秒</template></el-table-column>
      <el-table-column label="自动监控" width="100"><template slot-scope="scope"><el-tag :type="scope.row.enabled ? 'success' : 'info'" size="small">{{ scope.row.enabled ? '启用' : '停用' }}</el-tag></template></el-table-column>
      <el-table-column label="操作" width="230" fixed="right">
        <template slot-scope="scope">
          <el-button type="text" :icon="scope.row.enabled ? 'el-icon-video-pause' : 'el-icon-video-play'" :loading="togglingId === scope.row.id" @click="toggleMonitor(scope.row)">{{ scope.row.enabled ? '关闭监测' : '启动监测' }}</el-button>
          <el-button type="text" icon="el-icon-edit" @click="openEdit(scope.row)">编辑</el-button>
          <el-button type="text" class="danger-action" icon="el-icon-delete" @click="remove(scope.row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog :title="form.id ? '编辑服务器' : '添加服务器'" :visible.sync="dialogVisible" width="720px" append-to-body>
      <el-form ref="serverForm" :model="form" :rules="rules" label-width="130px">
        <el-row :gutter="16">
          <el-col :span="12"><el-form-item label="服务器名称" prop="name"><el-input v-model="form.name" placeholder="生产服务器-01" /></el-form-item></el-col>
          <el-col :span="12"><el-form-item label="服务器地址" prop="host"><el-input v-model="form.host" placeholder="192.168.1.100" /></el-form-item></el-col>
        </el-row>
        <el-row :gutter="16">
          <el-col :span="12"><el-form-item label="SSH 端口" prop="port"><el-input-number v-model="form.port" :min="1" :max="65535" controls-position="right" style="width:100%" /></el-form-item></el-col>
          <el-col :span="12"><el-form-item label="SSH 用户" prop="username"><el-input v-model="form.username" placeholder="monitor" /></el-form-item></el-col>
        </el-row>
        <el-form-item label="远程项目路径" prop="projectPath">
          <el-input v-model="form.projectPath" placeholder="/opt/miner_detector" />
          <div class="form-tip">SSH 登录后检测模型项目所在的 Linux 绝对路径。</div>
        </el-form-item>
        <el-form-item label="进程候选状态文件" prop="cpuResultFile">
          <el-input v-model="form.cpuResultFile" placeholder="results/candidate_state.json" />
          <div class="form-tip">候选文件：{{ fullCpuResultPath }}</div>
        </el-form-item>
        <el-form-item label="流量告警文件" prop="trafficAlertFile">
          <el-input v-model="form.trafficAlertFile" placeholder="results/alerts.jsonl" />
          <div class="form-tip">流量文件：{{ fullTrafficAlertPath }}</div>
        </el-form-item>
        <el-form-item label="随机探测目录" prop="randomObservationDir">
          <el-input v-model="form.randomObservationDir" placeholder="results/random_observations" />
          <div class="form-tip">随机探测目录：{{ fullRandomObservationPath }}</div>
        </el-form-item>
        <el-form-item label="认证方式" prop="authType"><el-radio-group v-model="form.authType"><el-radio label="key">SSH 密钥</el-radio><el-radio label="password">密码</el-radio></el-radio-group></el-form-item>
        <el-form-item v-if="form.authType === 'key'" label="私钥文件" prop="identityFile">
          <el-input v-model="form.identityFile" readonly placeholder="请选择客户端本机的 SSH 私钥"><el-button slot="append" icon="el-icon-folder-opened" @click="selectKey">选择</el-button></el-input>
        </el-form-item>
        <el-form-item v-else label="SSH 密码" prop="password" :required="!form.id || !form.hasPassword">
          <el-input v-model="form.password" type="password" show-password :placeholder="form.hasPassword ? '已安全保存，留空表示不修改' : '输入 SSH 密码'" autocomplete="new-password" />
        </el-form-item>
        <el-form-item label="主机指纹">
          <el-input v-model="form.hostFingerprint" placeholder="SHA-256 指纹（ssh-keyscan 获取）" />
          <div class="form-tip">建议固定服务器主机指纹，防止中间人攻击。</div>
        </el-form-item>
        <el-form-item label="首次信任"><el-checkbox v-model="form.allowUntrustedHost">暂时允许未验证主机（仅限受控测试环境）</el-checkbox></el-form-item>
        <el-row :gutter="16">
          <el-col :span="12"><el-form-item label="检测间隔"><el-input-number v-model="form.checkInterval" :min="2" :max="300" controls-position="right" style="width:100%" /></el-form-item></el-col>
          <el-col :span="12"><el-form-item label="自动监控"><el-switch v-model="form.enabled" /></el-form-item></el-col>
        </el-row>
      </el-form>
      <div v-if="form.id" class="dialog-tools">
        <div class="dialog-tools__icon"><i class="el-icon-connection" /></div>
        <div class="dialog-tools__content">
          <strong>连接与结果</strong>
          <p>使用已保存配置执行连接测试或读取进程候选、流量告警与随机探测结果；修改表单后请先保存。</p>
        </div>
        <div class="dialog-tools__actions">
          <el-button plain icon="el-icon-connection" :loading="testingId === form.id" @click="test(form)">测试连接</el-button>
          <el-button type="primary" icon="el-icon-refresh" :loading="detectingId === form.id" @click="detect(form)">获取全部</el-button>
        </div>
      </div>
      <div slot="footer">
        <el-button @click="dialogVisible=false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存</el-button>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { desktopApi, isDesktopClient } from '@/api/desktop'

const emptyForm = () => ({ id: '', name: '', host: '', port: 22, username: 'monitor', projectPath: '/opt/miner_detector', cpuResultFile: 'results/candidate_state.json', trafficAlertFile: 'results/alerts.jsonl', randomObservationDir: 'results/random_observations', authType: 'key', identityFile: '', password: '', hasPassword: false, enabled: true, checkInterval: 5, hostFingerprint: '', allowUntrustedHost: false })
const relativeFileRule = /^[A-Za-z0-9._/ +:-]+$/

export default {
  name: 'RemoteServers',
  data() {
    return {
      desktop: isDesktopClient(), loading: false, saving: false, testingId: '', detectingId: '', togglingId: '', dialogVisible: false,
      servers: [], statuses: {}, form: emptyForm(), unsubscribers: [],
      rules: {
        name: [{ required: true, message: '请输入服务器名称', trigger: 'blur' }],
        host: [{ required: true, message: '请输入服务器地址', trigger: 'blur' }],
        username: [{ required: true, message: '请输入 SSH 用户名', trigger: 'blur' }],
        projectPath: [{ required: true, message: '请输入远程项目路径', trigger: 'blur' }, { pattern: /^\/[A-Za-z0-9._/ +:-]+$/, message: '请输入 Linux 绝对路径', trigger: 'blur' }],
        cpuResultFile: [{ required: true, message: '请输入进程候选状态文件', trigger: 'blur' }, { validator: this.validateRelativeFile, trigger: 'blur' }],
        trafficAlertFile: [{ required: true, message: '请输入流量告警文件', trigger: 'blur' }, { validator: this.validateRelativeFile, trigger: 'blur' }],
        randomObservationDir: [{ required: true, message: '请输入随机探测目录', trigger: 'blur' }, { validator: this.validateRelativeDir, trigger: 'blur' }],
        identityFile: [{ validator: (_rule, value, callback) => this.form.authType !== 'key' || value ? callback() : callback(new Error('请选择 SSH 私钥')), trigger: 'change' }],
        password: [{ validator: (_rule, value, callback) => this.form.authType !== 'password' || value || this.form.hasPassword ? callback() : callback(new Error('请输入 SSH 密码')), trigger: 'blur' }]
      }
    }
  },
  computed: {
    fullCpuResultPath() { return this.fullPath(this.form.cpuResultFile) },
    fullTrafficAlertPath() { return this.fullPath(this.form.trafficAlertFile) },
    fullRandomObservationPath() { return this.fullPath(this.form.randomObservationDir) }
  },
  created() {
    if (!this.desktop) return
    this.load()
    this.unsubscribers = [
      desktopApi.onSshStatus(event => this.applyStatusEvent(event)),
      desktopApi.onDetectionStatus(event => this.applyStatusEvent(event)),
      desktopApi.onDetectionError(event => {
        this.applyStatusEvent({ ...event, status: 'error' })
        if (event && event.message) this.$message.error(event.message)
      })
    ]
  },
  beforeDestroy() { this.unsubscribers.forEach(unsubscribe => unsubscribe()) },
  methods: {
    validateRelativeFile(_rule, value, callback) {
      const text = String(value || '').trim()
      if (!relativeFileRule.test(text) || text.startsWith('/') || text.split('/').includes('..') || !text.split('/').pop().includes('.')) return callback(new Error('请输入包含文件名的项目内相对路径'))
      callback()
    },
    validateRelativeDir(_rule, value, callback) {
      const text = String(value || '').trim().replace(/\/+$/, '')
      if (!text || !relativeFileRule.test(text) || text.startsWith('/') || text.split('/').includes('..')) return callback(new Error('请输入项目内相对目录路径'))
      callback()
    },
    fullPath(relativeFile) {
      const root = String(this.form.projectPath || '').replace(/\/+$/, '')
      const relative = String(relativeFile || '').replace(/^\/+/, '')
      return root && relative ? `${root}/${relative}` : '-'
    },
    applyStatusEvent(event) {
      if (!event || !event.serverId || !event.status) return
      const current = this.statuses[event.serverId]
      if (event.status === 'connected' && current === 'detecting') return
      this.$set(this.statuses, event.serverId, event.status)
    },
    applySummaryStatuses(summary) {
      const summaryServers = summary && Array.isArray(summary.servers) ? summary.servers : []
      summaryServers.forEach(server => {
        const runtimeStatus = server.runtimeStatus || {}
        if (runtimeStatus.status) this.$set(this.statuses, server.id, runtimeStatus.status)
      })
      this.servers.forEach(server => {
        if (server.enabled === false) this.$set(this.statuses, server.id, 'disabled')
        else if (!this.statuses[server.id]) this.$set(this.statuses, server.id, 'offline')
      })
    },
    async load() {
      this.loading = true
      try {
        const [servers, summary] = await Promise.all([desktopApi.listServers(), desktopApi.getSummary()])
        this.servers = servers || []
        this.applySummaryStatuses(summary)
      } finally {
        this.loading = false
      }
    },
    openCreate() { this.form = emptyForm(); this.dialogVisible = true; this.$nextTick(() => this.$refs.serverForm && this.$refs.serverForm.clearValidate()) },
    openEdit(server) { this.form = { ...emptyForm(), ...server, password: '' }; this.dialogVisible = true; this.$nextTick(() => this.$refs.serverForm && this.$refs.serverForm.clearValidate()) },
    selectKey() { desktopApi.selectIdentityFile().then(file => { if (file) this.form.identityFile = file }) },
    save() {
      this.$refs.serverForm.validate(async valid => {
        if (!valid) return
        if (this.form.authType === 'password' && !this.form.password && !this.form.hasPassword) return this.$message.warning('请输入 SSH 密码')
        if (!this.form.hostFingerprint && !this.form.allowUntrustedHost) return this.$message.warning('请填写主机指纹，或明确允许测试环境首次信任')
        this.saving = true
        try { await desktopApi.saveServer({ ...this.form }); this.$message.success('服务器配置已保存'); this.dialogVisible = false; await this.load() }
        catch (error) { this.$message.error(error.message || String(error)) }
        finally { this.saving = false }
      })
    },
    async test(server) {
      this.testingId = server.id
      try {
        const result = await desktopApi.testConnection(server.id)
        this.$set(this.statuses, server.id, 'connected')
        const suffix = `，进程文件${result.cpuResultExists ? '可读取' : '未生成'}，流量文件${result.trafficAlertExists ? '可读取' : '未生成'}，随机探测目录${result.randomObservationExists ? '可读取' : '未生成'}`
        this.$message.success(`SSH 连接成功，延迟 ${result.latency}ms${suffix}`)
      }
      catch (error) { this.$set(this.statuses, server.id, 'error'); this.$message.error(error.message || String(error)) }
      finally { this.testingId = '' }
    },
    async detect(server) {
      this.detectingId = server.id
      try { await desktopApi.runDetection(server.id, 'all'); this.$set(this.statuses, server.id, 'online'); this.$message.success('进程候选、流量告警与随机探测结果已获取') }
      catch (error) { this.$set(this.statuses, server.id, 'error'); this.$message.error(error.message || String(error)) }
      finally { this.detectingId = '' }
    },
    async toggleMonitor(server) {
      this.togglingId = server.id
      const enabled = !server.enabled
      try {
        await desktopApi.saveServer({ ...server, enabled, password: '' })
        this.$set(this.statuses, server.id, enabled ? 'detecting' : 'disabled')
        this.$message.success(enabled ? '已启动监测' : '已关闭监测')
        await this.load()
      } catch (error) {
        this.$message.error(error.message || String(error))
      } finally {
        this.togglingId = ''
      }
    },
    remove(server) {
      this.$confirm(`确定删除服务器“${server.name}”吗？`, '删除确认', { type: 'warning' }).then(async () => {
        await desktopApi.removeServer(server.id); this.$message.success('已删除'); await this.load()
      }).catch(() => {})
    },
    statusOf(server) { return server.enabled === false ? 'disabled' : (this.statuses[server.id] || 'offline') },
    statusText(status) { return ({ connected: '在线', online: '在线', detecting: '检测中', reconnecting: '重连中', error: '异常', disconnected: '离线', offline: '离线', disabled: '已关闭' })[status] || status }
  }
}
</script>

<style lang="scss" scoped>
.remote-servers { min-height: calc(100vh - 84px); background: #f4f7fa; }
.page-heading { display:flex; align-items:center; justify-content:space-between; margin-bottom:22px; padding:26px 30px; color:#fff; border-radius:16px; background:linear-gradient(120deg,#132943,#176766); }
.page-heading span { color:#63dcd2; font-size:11px; font-weight:700; letter-spacing:2px; }
.page-heading h2 { margin:7px 0; }
.page-heading p { margin:0; color:#c9d8e3; }
.server-table { margin-top:18px; padding:8px 16px; border-radius:12px; }
.status-pill { display:inline-block; padding:4px 9px; color:#6e7e8e; font-size:11px; border-radius:10px; background:#edf1f4; }
.status-pill.connected,.status-pill.online { color:#138568; background:#ddf5eb; }
.status-pill.error { color:#bf4047; background:#fde5e6; }
.status-pill.detecting,.status-pill.reconnecting { color:#a66a0c; background:#fff0d3; }
.status-pill.disabled { color:#7c8792; background:#eef1f4; }
.danger-action { color:#d94a50; }
.form-tip { color:#909baa; font-size:12px; line-height:1.7; }
.dialog-tools { display:flex; align-items:center; gap:14px; margin:6px 0 18px; padding:16px; border:1px solid #dfe8f2; border-radius:14px; background:linear-gradient(135deg, #f8fbff 0%, #f3f8fd 100%); box-shadow:0 8px 20px rgba(31, 69, 104, .05); }
.dialog-tools__icon { display:flex; align-items:center; justify-content:center; flex:0 0 42px; width:42px; height:42px; color:#168f88; font-size:20px; border-radius:12px; background:#e5f7f4; }
.dialog-tools__content { flex:1; min-width:0; }
.dialog-tools__content strong { display:block; color:#31465a; font-size:15px; line-height:1.4; }
.dialog-tools__content p { margin:4px 0 0; color:#8b98a7; font-size:12px; line-height:1.6; }
.dialog-tools__actions { display:flex; align-items:center; gap:10px; }
.dialog-tools__actions .el-button { min-width:104px; height:36px; padding:9px 14px; border-radius:10px; font-weight:500; }
.path-cell strong,.path-cell small { display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.path-cell strong { color:#34485b; font-weight:500; }
.path-cell small { margin-top:4px; color:#8a98a6; }
@media (max-width: 680px) { .dialog-tools { align-items:flex-start; flex-wrap:wrap; }.dialog-tools__actions { width:100%; }.dialog-tools__actions .el-button { flex:1; } }
</style>