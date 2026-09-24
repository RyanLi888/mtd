package com.mtd.quartz.task;

import org.springframework.stereotype.Component;
import com.mtd.common.utils.StringUtils;

/**
 * 定时任务调用示例。
 */
@Component("systemTask")
public class SystemTask
{
    public void multipleParams(String text, Boolean enabled, Long delay, Double ratio, Integer count)
    {
        System.out.println(StringUtils.format("执行多参方法：字符串{}，布尔{}，长整型{}，浮点型{}，整型{}",
                text, enabled, delay, ratio, count));
    }

    public void withParams(String params)
    {
        System.out.println("执行有参方法：" + params);
    }

    public void noParams()
    {
        System.out.println("执行无参方法");
    }
}
