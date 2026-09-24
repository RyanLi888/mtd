package com.mtd.detector.service.impl;

import java.util.List;

import org.apache.ibatis.annotations.Select;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.mtd.detector.mapper.trafficMapper;
import com.mtd.detector.domain.traffic;
import com.mtd.detector.service.ItrafficService;

/**
 * 恶意流量信息Service业务层处理
 * 
 * @author lixu
 * @date 2025-05-19
 */
@Service
public class trafficServiceImpl implements ItrafficService 
{
    @Autowired
    private trafficMapper trafficMapper;

    /**
     * 查询恶意流量信息
     * 
     * @param trafficId 恶意流量信息主键
     * @return 恶意流量信息
     */
    @Override
    public traffic selecttrafficByTrafficId(Long trafficId)
    {
        return trafficMapper.selecttrafficByTrafficId(trafficId);
    }

    /**
     * 查询恶意流量信息列表
     * 
     * @param traffic 恶意流量信息
     * @return 恶意流量信息
     */
    @Override
    public List<traffic> selecttrafficList(traffic traffic)
    {
        return trafficMapper.selecttrafficList(traffic);
    }

    /**
     * 新增恶意流量信息
     * 
     * @param traffic 恶意流量信息
     * @return 结果
     */
    @Override
    public int inserttraffic(traffic traffic)
    {
        return trafficMapper.inserttraffic(traffic);
    }

    /**
     * 修改恶意流量信息
     * 
     * @param traffic 恶意流量信息
     * @return 结果
     */
    @Override
    public int updatetraffic(traffic traffic)
    {
        return trafficMapper.updatetraffic(traffic);
    }

    /**
     * 批量删除恶意流量信息
     * 
     * @param trafficIds 需要删除的恶意流量信息主键
     * @return 结果
     */
    @Override
    public int deletetrafficByTrafficIds(Long[] trafficIds)
    {
        return trafficMapper.deletetrafficByTrafficIds(trafficIds);
    }

    /**
     *
     * @param trafficList
     * @param updateSupport
     * @param operName
     * @return
     *  导入数据在这里校验，可修改相应校验规则作为导入。
     */
    @Override
    public String importTraffic(List<traffic> trafficList, boolean updateSupport, String operName) {
        if (trafficList == null || trafficList.isEmpty()) {
            return "导入数据为空，操作失败";
        }

        int successNum = 0;  // 成功条数
        int failureNum = 0;  // 失败条数
        StringBuilder successMsg = new StringBuilder();
        StringBuilder failureMsg = new StringBuilder();

        // 遍历导入的流量数据
        for (traffic traffic : trafficList) {
            try {
                // 1. 数据校验（示例：流量ID非空）
                if (traffic.getTrafficId() == null) {
                    failureNum++;
                    failureMsg.append("<br/>第 ").append(successNum + failureNum).append(" 条数据：流量ID不能为空");
                    continue;
                }

                // 2. 检查数据是否已存在（根据业务主键，如流量ID）
                traffic existTraffic = trafficMapper.selecttrafficByTrafficId(traffic.getTrafficId());
                if (existTraffic != null) {
                    if (updateSupport) {
                        // 覆盖更新：设置更新人信息（BaseEntity 字段）
                        traffic.setUpdateBy(operName);
                        trafficMapper.updatetraffic(traffic);
                        successNum++;
                        successMsg.append("<br/>第 ").append(successNum + failureNum).append(" 条数据：更新成功");
                    } else {
                        failureNum++;
                        failureMsg.append("<br/>第 ").append(successNum + failureNum).append(" 条数据：流量ID已存在，未更新");
                    }
                    continue;
                }

                // 3. 新增数据：设置创建人信息（BaseEntity 字段）
                traffic.setCreateBy(operName);
                trafficMapper.inserttraffic(traffic);
                successNum++;
                successMsg.append("<br/>第 ").append(successNum + failureNum).append(" 条数据：新增成功");

            } catch (Exception e) {
                failureNum++;
                failureMsg.append("<br/>第 ").append(successNum + failureNum).append(" 条数据：导入失败，原因：").append(e.getMessage());
            }
        }

        // 组装结果提示
        if (failureNum > 0) {
            successMsg.insert(0, "警告：成功导入 " + successNum + " 条数据，失败 " + failureNum + " 条数据。原因：");
            return successMsg.toString() + failureMsg;
        } else {
            return "成功导入 " + successNum + " 条数据" + successMsg;
        }
    }

    /**
     * 删除恶意流量信息信息
     * 
     * @param trafficId 恶意流量信息主键
     * @return 结果
     */
    @Override
    public int deletetrafficByTrafficId(Long trafficId)
    {
        return trafficMapper.deletetrafficByTrafficId(trafficId);
    }
}
