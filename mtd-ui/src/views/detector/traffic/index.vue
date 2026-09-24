<template>
  <div class="app-container">
    <el-form :model="queryParams" ref="queryForm" size="small" :inline="true" v-show="showSearch" label-width="68px">
      <el-form-item label="源IP地址" prop="sourceIp">
        <el-input
          v-model="queryParams.sourceIp"
          placeholder="请输入源IP地址"
          clearable
          @keyup.enter.native="handleQuery"
        />
      </el-form-item>
      <el-form-item label="流量时间" prop="trafficTime">
        <el-date-picker clearable
          v-model="queryParams.trafficTime"
          type="date"
          value-format="yyyy-MM-dd"
          placeholder="请选择流量时间">
        </el-date-picker>
      </el-form-item>
      <el-form-item label="威胁等级" prop="threatLevel">
        <el-select v-model="queryParams.threatLevel" placeholder="请选择威胁等级" clearable>
          <el-option
            v-for="dict in dict.type.mtd_traffic_grade"
            :key="dict.value"
            :label="dict.label"
            :value="dict.value"
          />
        </el-select>
      </el-form-item>
      <el-form-item>
        <el-button type="primary" icon="el-icon-search" size="mini" @click="handleQuery">搜索</el-button>
        <el-button icon="el-icon-refresh" size="mini" @click="resetQuery">重置</el-button>
      </el-form-item>
    </el-form>

    <el-row :gutter="10" class="mb8">
      <el-col :span="1.5">
        <el-button
          type="primary"
          plain
          icon="el-icon-plus"
          size="mini"
          @click="handleAdd"
          v-hasPermi="['detector:traffic:add']"
        >新增</el-button>
      </el-col>
      <el-col :span="1.5">
        <el-button
          type="success"
          plain
          icon="el-icon-edit"
          size="mini"
          :disabled="single"
          @click="handleUpdate"
          v-hasPermi="['detector:traffic:edit']"
        >修改</el-button>
      </el-col>
      <el-col :span="1.5">
        <el-button
          type="danger"
          plain
          icon="el-icon-delete"
          size="mini"
          :disabled="multiple"
          @click="handleDelete"
          v-hasPermi="['detector:traffic:remove']"
        >删除</el-button>
      </el-col>
      <el-col :span="1.5">
        <el-button
          type="warning"
          plain
          icon="el-icon-download"
          size="mini"
          @click="handleExport"
          v-hasPermi="['detector:traffic:export']"
        >导出</el-button>
      </el-col>
      <el-col :span="1.5">
        <el-button type="info" plain icon="el-icon-upload2" size="mini" @click="handleImport" v-hasPermi="['system:user:import']">导入</el-button>
      </el-col>
      <right-toolbar :showSearch.sync="showSearch" @queryTable="getList"></right-toolbar>
    </el-row>

    <el-table v-loading="loading" :data="trafficList" @selection-change="handleSelectionChange">
      <el-table-column type="selection" width="55" align="center" />
      <el-table-column label="流量ID" align="center" prop="trafficId" />
      <el-table-column label="源IP地址" align="center" prop="sourceIp" />
      <el-table-column label="目标IP地址" align="center" prop="destinationIp" />
      <el-table-column label="流量时间" align="center" prop="trafficTime" width="180">
        <template slot-scope="scope">
          <span>{{ parseTime(scope.row.trafficTime, '{y}-{m}-{d}') }}</span>
        </template>
      </el-table-column>
      <el-table-column label="威胁等级" align="center" prop="threatLevel">
        <template slot-scope="scope">
          <dict-tag :options="dict.type.mtd_traffic_grade" :value="scope.row.threatLevel"/>
        </template>
      </el-table-column>
      <el-table-column label="操作" align="center" class-name="small-padding fixed-width">
        <template slot-scope="scope">
          <el-button
            size="mini"
            type="text"
            icon="el-icon-edit"
            @click="handleUpdate(scope.row)"
            v-hasPermi="['detector:traffic:edit']"
          >修改</el-button>
          <el-button
            size="mini"
            type="text"
            icon="el-icon-delete"
            @click="handleDelete(scope.row)"
            v-hasPermi="['detector:traffic:remove']"
          >删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <pagination
      v-show="total>0"
      :total="total"
      :page.sync="queryParams.pageNum"
      :limit.sync="queryParams.pageSize"
      @pagination="getList"
    />

    <!-- 添加或修改恶意流量信息对话框 -->
    <el-dialog :title="title" :visible.sync="open" width="500px" append-to-body>
      <el-form ref="form" :model="form" :rules="rules" label-width="80px">
        <el-form-item label="源IP地址" prop="sourceIp">
          <el-input v-model="form.sourceIp" placeholder="请输入源IP地址" />
        </el-form-item>
        <el-form-item label="目标IP地址" prop="destinationIp">
          <el-input v-model="form.destinationIp" placeholder="请输入目标IP地址" />
        </el-form-item>
        <el-form-item label="流量时间" prop="trafficTime">
          <el-date-picker clearable
            v-model="form.trafficTime"
            type="date"
            value-format="yyyy-MM-dd"
            placeholder="请选择流量时间">
          </el-date-picker>
        </el-form-item>
        <el-form-item label="威胁等级" prop="threatLevel">
          <el-radio-group v-model="form.threatLevel">
            <el-radio
              v-for="dict in dict.type.mtd_traffic_grade"
              :key="dict.value"
              :label="dict.value"
            >{{dict.label}}</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <div slot="footer" class="dialog-footer">
        <el-button type="primary" @click="submitForm">确 定</el-button>
        <el-button @click="cancel">取 消</el-button>
      </div>
    </el-dialog>

    <!-- 用户导入对话框 -->
    <el-dialog :title="upload.title" :visible.sync="upload.open" width="400px" append-to-body>
      <el-upload ref="upload" :limit="1" accept=".xlsx, .xls" :headers="upload.headers" :action="upload.url + '?updateSupport=' + upload.updateSupport" :disabled="upload.isUploading" :on-progress="handleFileUploadProgress" :on-success="handleFileSuccess" :auto-upload="false" drag>
        <i class="el-icon-upload"></i>
        <div class="el-upload__text">将文件拖到此处，或<em>点击上传</em></div>
        <div class="el-upload__tip text-center" slot="tip">
          <div class="el-upload__tip" slot="tip">
            <el-checkbox v-model="upload.updateSupport" />是否更新已经存在的用户数据
          </div>
          <span>仅允许导入xls、xlsx格式文件。</span>
          <el-link type="primary" :underline="false" style="font-size: 12px; vertical-align: baseline" @click="importTemplate">下载模板</el-link>
        </div>
      </el-upload>
      <div slot="footer" class="dialog-footer">
        <el-button type="primary" @click="submitFileForm">确 定</el-button>
        <el-button @click="upload.open = false">取 消</el-button>
      </div>
    </el-dialog>

  </div>
</template>

<script>
import { listTraffic, getTraffic, delTraffic, addTraffic, updateTraffic } from "@/api/detector/traffic"
import { getToken } from "@/utils/auth";
export default {
  name: "Traffic",
  dicts: ['mtd_traffic_grade'],
  data() {
    return {
      // 遮罩层
      loading: true,
      // 选中数组
      ids: [],
      // 非单个禁用
      single: true,
      // 非多个禁用
      multiple: true,
      // 显示搜索条件
      showSearch: true,
      // 总条数
      total: 0,
      // 恶意流量信息表格数据
      trafficList: [],
      // 弹出层标题
      title: "",
      // 是否显示弹出层
      open: false,
      // 查询参数
      queryParams: {
        pageNum: 1,
        pageSize: 10,
        sourceIp: null,
        trafficTime: null,
        threatLevel: null
      },
      // 表单参数
      form: {},
      // 用户导入参数
      upload: {
        // 是否显示弹出层（用户导入）
        open: false,
        // 弹出层标题（用户导入）
        title: "信息导入",
        // 是否禁用上传
        isUploading: false,
        // 是否更新已经存在的用户数据
        updateSupport: 0,
        // 设置上传的请求头部
        headers: { Authorization: "Bearer " + getToken() },
        // 上传的地址
        url: process.env.VUE_APP_BASE_API + "/detector/traffic/importData"
      },
      // 列信息
      columns: [
        { key: 0, label: `源IP地址`, visible: true },
        { key: 1, label: `目的IP地址`, visible: true },
        { key: 2, label: `流量时间`, visible: true },
        { key: 3, label: `威胁等级`, visible: true },
      ],
      // 表单校验
      rules: {
        // sourceIp: [
        //   { required: true, message: "源IP不能为空", trigger: "blur" },
        //   // { min: 2, max: 20, message: '用户名称长度必须介于 2 和 20 之间', trigger: 'blur' }
        // ],
        // destinationIp: [
        //   { required: true, message: "目的IP不能为空", trigger: "blur" }
        // ]
        // password: [
        //   { required: true, message: "用户密码不能为空", trigger: "blur" },
        //   { min: 5, max: 20, message: '用户密码长度必须介于 5 和 20 之间', trigger: 'blur' },
        //   { pattern: /^[^<>"'|\\]+$/, message: "不能包含非法字符：< > \" ' \\\ |", trigger: "blur" }
        // ],
        // email: [
        //   {
        //     type: "email",
        //     message: "请输入正确的邮箱地址",
        //     trigger: ["blur", "change"]
        //   }
        // ],
        // phonenumber: [
        //   {
        //     pattern: /^1[3|4|5|6|7|8|9][0-9]\d{8}$/,
        //     message: "请输入正确的手机号码",
        //     trigger: "blur"
        //   }
        // ]
      }
    }
  },
  created() {
    this.getList()
  },
  methods: {
    /** 查询恶意流量信息列表 */
    getList() {
      this.loading = true
      listTraffic(this.queryParams).then(response => {
        this.trafficList = response.rows
        this.total = response.total
        this.loading = false
      })
    },
    // 取消按钮
    cancel() {
      this.open = false
      this.reset()
    },
    // 表单重置
    reset() {
      this.form = {
        trafficId: null,
        sourceIp: null,
        destinationIp: null,
        trafficTime: null,
        threatLevel: null
      }
      this.resetForm("form")
    },
    /** 搜索按钮操作 */
    handleQuery() {
      this.queryParams.pageNum = 1
      this.getList()
    },
    /** 重置按钮操作 */
    resetQuery() {
      this.resetForm("queryForm")
      this.handleQuery()
    },
    /** 导入按钮操作 */
    handleImport() {
      this.upload.title = "信息导入"
      this.upload.open = true
    },
    // /** 下载模板操作 */
    // importTemplate() {
    //   this.download('detector/traffic/importTemplate', {
    //   }, `traffic_information.xlsx`)
    // },
    /** 下载模板操作 */
    importTemplate() {
      this.download('/detector/traffic/importTemplate', {
      }, `traffic_information_${new Date().getTime()}.xlsx`)
    },
    // 文件上传中处理
    handleFileUploadProgress(event, file, fileList) {
      this.upload.isUploading = true
    },
    // 文件上传成功处理
    handleFileSuccess(response, file, fileList) {
      this.upload.open = false
      this.upload.isUploading = false
      this.$refs.upload.clearFiles()
      this.$alert("<div style='overflow: auto;overflow-x: hidden;max-height: 70vh;padding: 10px 20px 0;'>" + response.msg + "</div>", "导入结果", { dangerouslyUseHTMLString: true })
      this.getList()
    },
    // 提交上传文件
    submitFileForm() {
      this.$refs.upload.submit()
    },
    // 多选框选中数据
    handleSelectionChange(selection) {
      this.ids = selection.map(item => item.trafficId)
      this.single = selection.length!==1
      this.multiple = !selection.length
    },
    /** 新增按钮操作 */
    handleAdd() {
      this.reset()
      this.open = true
      this.title = "添加恶意流量信息"
    },
    /** 修改按钮操作 */
    handleUpdate(row) {
      this.reset()
      const trafficId = row.trafficId || this.ids
      getTraffic(trafficId).then(response => {
        this.form = response.data
        this.open = true
        this.title = "修改恶意流量信息"
      })
    },
    /** 提交按钮 */
    submitForm() {
      this.$refs["form"].validate(valid => {
        if (valid) {
          if (this.form.trafficId != null) {
            updateTraffic(this.form).then(response => {
              this.$modal.msgSuccess("修改成功")
              this.open = false
              this.getList()
            })
          } else {
            addTraffic(this.form).then(response => {
              this.$modal.msgSuccess("新增成功")
              this.open = false
              this.getList()
            })
          }
        }
      })
    },
    /** 删除按钮操作 */
    handleDelete(row) {
      const trafficIds = row.trafficId || this.ids
      this.$modal.confirm('是否确认删除恶意流量信息编号为"' + trafficIds + '"的数据项？').then(function() {
        return delTraffic(trafficIds)
      }).then(() => {
        this.getList()
        this.$modal.msgSuccess("删除成功")
      }).catch(() => {})
    },
    /** 导出按钮操作 */
    handleExport() {
      this.download('detector/traffic/export', {
        ...this.queryParams
      }, `traffic_${new Date().getTime()}.xlsx`)
    }
  }
}
</script>
