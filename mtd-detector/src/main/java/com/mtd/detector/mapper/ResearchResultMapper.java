package com.mtd.detector.mapper;

import java.util.List;
import com.mtd.detector.domain.ResearchResult;

/**
 * 科研成果Mapper接口
 * 
 * @author lixu
 * @date 2025-05-19
 */
public interface ResearchResultMapper 
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
     * 删除科研成果
     * 
     * @param resultId 科研成果主键
     * @return 结果
     */
    public int deleteResearchResultByResultId(Long resultId);

    /**
     * 批量删除科研成果
     * 
     * @param resultIds 需要删除的数据主键集合
     * @return 结果
     */
    public int deleteResearchResultByResultIds(Long[] resultIds);
}
