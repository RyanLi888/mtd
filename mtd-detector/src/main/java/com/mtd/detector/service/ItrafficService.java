package com.mtd.detector.service;

import java.util.List;
import com.mtd.detector.domain.traffic;

/**
 * 恶意流量信息Service接口
 * 
 * @author lixu
 * @date 2025-05-19
 */
public interface ItrafficService 
{
    /**
     * 查询恶意流量信息
     * 
     * @param trafficId 恶意流量信息主键
     * @return 恶意流量信息
     */
    public traffic selecttrafficByTrafficId(Long trafficId);

    /**
     * 查询恶意流量信息列表
     * 
     * @param traffic 恶意流量信息
     * @return 恶意流量信息集合
     */
    public List<traffic> selecttrafficList(traffic traffic);

    /**
     * 新增恶意流量信息
     * 
     * @param traffic 恶意流量信息
     * @return 结果
     */
    public int inserttraffic(traffic traffic);

    /**
     * 修改恶意流量信息
     * 
     * @param traffic 恶意流量信息
     * @return 结果
     */
    public int updatetraffic(traffic traffic);

    /**
     * 批量删除恶意流量信息
     * 
     * @param trafficIds 需要删除的恶意流量信息主键集合
     * @return 结果
     */
    public int deletetrafficByTrafficIds(Long[] trafficIds);

    /**
     * 删除恶意流量信息信息
     * 
     * @param trafficId 恶意流量信息主键
     * @return 结果
     */
    public int deletetrafficByTrafficId(Long trafficId);

    String importTraffic(List<traffic> trafficList, boolean updateSupport, String operName);
}
