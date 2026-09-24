package com.mtd.detector.service.impl;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.mtd.detector.mapper.ResearchResultMapper;
import com.mtd.detector.domain.ResearchResult;
import com.mtd.detector.service.IResearchResultService;

/**
 * 科研成果Service业务层处理
 * 
 * @author lixu
 * @date 2025-05-19
 */
@Service
public class ResearchResultServiceImpl implements IResearchResultService 
{
    @Autowired
    private ResearchResultMapper researchResultMapper;

    /**
     * 查询科研成果
     * 
     * @param resultId 科研成果主键
     * @return 科研成果
     */
    @Override
    public ResearchResult selectResearchResultByResultId(Long resultId)
    {
        return researchResultMapper.selectResearchResultByResultId(resultId);
    }

    /**
     * 查询科研成果列表
     * 
     * @param researchResult 科研成果
     * @return 科研成果
     */
    @Override
    public List<ResearchResult> selectResearchResultList(ResearchResult researchResult)
    {
        return researchResultMapper.selectResearchResultList(researchResult);
    }

    /**
     * 新增科研成果
     * 
     * @param researchResult 科研成果
     * @return 结果
     */
    @Override
    public int insertResearchResult(ResearchResult researchResult)
    {
        return researchResultMapper.insertResearchResult(researchResult);
    }

    /**
     * 修改科研成果
     * 
     * @param researchResult 科研成果
     * @return 结果
     */
    @Override
    public int updateResearchResult(ResearchResult researchResult)
    {
        return researchResultMapper.updateResearchResult(researchResult);
    }

    /**
     * 批量删除科研成果
     * 
     * @param resultIds 需要删除的科研成果主键
     * @return 结果
     */
    @Override
    public int deleteResearchResultByResultIds(Long[] resultIds)
    {
        return researchResultMapper.deleteResearchResultByResultIds(resultIds);
    }

    /**
     * 删除科研成果信息
     * 
     * @param resultId 科研成果主键
     * @return 结果
     */
    @Override
    public int deleteResearchResultByResultId(Long resultId)
    {
        return researchResultMapper.deleteResearchResultByResultId(resultId);
    }
}
