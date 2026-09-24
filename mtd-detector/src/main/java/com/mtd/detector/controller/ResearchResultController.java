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
import com.mtd.detector.domain.ResearchResult;
import com.mtd.detector.service.IResearchResultService;
import com.mtd.common.utils.poi.ExcelUtil;
import com.mtd.common.core.page.TableDataInfo;

/**
 * 科研成果Controller
 * 
 * @author lixu
 * @date 2025-05-19
 */
@RestController
@RequestMapping("/detector/result")
public class ResearchResultController extends BaseController
{
    @Autowired
    private IResearchResultService researchResultService;

    /**
     * 查询科研成果列表
     */
    @PreAuthorize("@ss.hasPermi('detector:result:list')")
    @GetMapping("/list")
    public TableDataInfo list(ResearchResult researchResult)
    {
        startPage();
        List<ResearchResult> list = researchResultService.selectResearchResultList(researchResult);
        return getDataTable(list);
    }

    /**
     * 导出科研成果列表
     */
    @PreAuthorize("@ss.hasPermi('detector:result:export')")
    @Log(title = "科研成果", businessType = BusinessType.EXPORT)
    @PostMapping("/export")
    public void export(HttpServletResponse response, ResearchResult researchResult)
    {
        List<ResearchResult> list = researchResultService.selectResearchResultList(researchResult);
        ExcelUtil<ResearchResult> util = new ExcelUtil<ResearchResult>(ResearchResult.class);
        util.exportExcel(response, list, "科研成果数据");
    }

    /**
     * 获取科研成果详细信息
     */
    @PreAuthorize("@ss.hasPermi('detector:result:query')")
    @GetMapping(value = "/{resultId}")
    public AjaxResult getInfo(@PathVariable("resultId") Long resultId)
    {
        return success(researchResultService.selectResearchResultByResultId(resultId));
    }

    /**
     * 新增科研成果
     */
    @PreAuthorize("@ss.hasPermi('detector:result:add')")
    @Log(title = "科研成果", businessType = BusinessType.INSERT)
    @PostMapping
    public AjaxResult add(@RequestBody ResearchResult researchResult)
    {
        return toAjax(researchResultService.insertResearchResult(researchResult));
    }

    /**
     * 修改科研成果
     */
    @PreAuthorize("@ss.hasPermi('detector:result:edit')")
    @Log(title = "科研成果", businessType = BusinessType.UPDATE)
    @PutMapping
    public AjaxResult edit(@RequestBody ResearchResult researchResult)
    {
        return toAjax(researchResultService.updateResearchResult(researchResult));
    }

    /**
     * 删除科研成果
     */
    @PreAuthorize("@ss.hasPermi('detector:result:remove')")
    @Log(title = "科研成果", businessType = BusinessType.DELETE)
	@DeleteMapping("/{resultIds}")
    public AjaxResult remove(@PathVariable Long[] resultIds)
    {
        return toAjax(researchResultService.deleteResearchResultByResultIds(resultIds));
    }
}
