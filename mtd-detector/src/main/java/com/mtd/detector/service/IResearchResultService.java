package com.mtd.detector.service;

import java.util.List;
import com.mtd.detector.domain.ResearchResult;

/**
 * 科研成果Service接口
 * 
 * @author lixu
 * @date 2025-05-19
 */
public interface IResearchResultService 
{
    /**
     * 查询科研成果
     * 
     * @param resultId 科研成果主键
     * @return 科研成果
     */
    public ResearchResult selectResearchResultByResultId(Long resultId);

    /**
     * 查询科研成果列表
     * 
     * @param researchResult 科研成果
     * @return 科研成果集合
     */
    public List<ResearchResult> selectResearchResultList(ResearchResult researchResult);

    /**
     * 新增科研成果
     * 
     * @param researchResult 科研成果
     * @return 结果
     */
    public int insertResearchResult(ResearchResult researchResult);

    /**
     * 修改科研成果
     * 
     * @param researchResult 科研成果
     * @return 结果
     */
    public int updateResearchResult(ResearchResult researchResult);

    /**
     * 批量删除科研成果
     * 
     * @param resultIds 需要删除的科研成果主键集合
     * @return 结果
     */
    public int deleteResearchResultByResultIds(Long[] resultIds);

    /**
     * 删除科研成果信息
     * 
     * @param resultId 科研成果主键
     * @return 结果
     */
    public int deleteResearchResultByResultId(Long resultId);
}
