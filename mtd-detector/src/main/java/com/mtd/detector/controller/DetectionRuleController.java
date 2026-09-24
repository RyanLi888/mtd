package com.mtd.detector.controller;

import java.util.List;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.mtd.common.annotation.Log;
import com.mtd.common.core.controller.BaseController;
import com.mtd.common.core.domain.AjaxResult;
import com.mtd.common.enums.BusinessType;
import com.mtd.detector.domain.DetectionRule;
import com.mtd.detector.service.IDetectionRuleService;
import com.mtd.common.utils.poi.ExcelUtil;
import com.mtd.common.core.page.TableDataInfo;

/**
 * 检测规则Controller
 * 
 * @author lixu
 * @date 2025-05-19
 */
@RestController
@RequestMapping("/detector/rule")
public class DetectionRuleController extends BaseController
{
    @Autowired
    private IDetectionRuleService detectionRuleService;

    /**
     * 查询检测规则列表
     */
    @PreAuthorize("@ss.hasPermi('detector:rule:list')")
    @GetMapping("/list")
    public TableDataInfo list(DetectionRule detectionRule)
    {
        startPage();
        List<DetectionRule> list = detectionRuleService.selectDetectionRuleList(detectionRule);
        return getDataTable(list);
    }

    /**
     * 导出检测规则列表
     */
    @PreAuthorize("@ss.hasPermi('detector:rule:export')")
    @Log(title = "检测规则", businessType = BusinessType.EXPORT)
    @PostMapping("/export")
    public void export(HttpServletResponse response, DetectionRule detectionRule)
    {
        List<DetectionRule> list = detectionRuleService.selectDetectionRuleList(detectionRule);
        ExcelUtil<DetectionRule> util = new ExcelUtil<DetectionRule>(DetectionRule.class);
        util.exportExcel(response, list, "检测规则数据");
    }

    /**
     * 获取检测规则详细信息
     */
    @PreAuthorize("@ss.hasPermi('detector:rule:query')")
    @GetMapping(value = "/{ruleId}")
    public AjaxResult getInfo(@PathVariable("ruleId") Long ruleId)
    {
        return success(detectionRuleService.selectDetectionRuleByRuleId(ruleId));
    }

    /**
     * 新增检测规则
     */
    @PreAuthorize("@ss.hasPermi('detector:rule:add')")
    @Log(title = "检测规则", businessType = BusinessType.INSERT)
    @PostMapping
    public AjaxResult add(@RequestBody DetectionRule detectionRule)
    {
        return toAjax(detectionRuleService.insertDetectionRule(detectionRule));
    }

    /**
     * 修改检测规则
     */
    @PreAuthorize("@ss.hasPermi('detector:rule:edit')")
    @Log(title = "检测规则", businessType = BusinessType.UPDATE)
    @PutMapping
    public AjaxResult edit(@RequestBody DetectionRule detectionRule)
    {
        return toAjax(detectionRuleService.updateDetectionRule(detectionRule));
    }

    /**
     * 删除检测规则
     */
    @PreAuthorize("@ss.hasPermi('detector:rule:remove')")
    @Log(title = "检测规则", businessType = BusinessType.DELETE)
	@DeleteMapping("/{ruleIds}")
    public AjaxResult remove(@PathVariable Long[] ruleIds)
    {
        return toAjax(detectionRuleService.deleteDetectionRuleByRuleIds(ruleIds));
    }
}
