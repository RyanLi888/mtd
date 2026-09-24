package com.mtd.framework.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.format.DateTimeFormatter;
import java.util.regex.Pattern;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.jdbc.datasource.init.ScriptUtils;
import org.springframework.util.StreamUtils;

/**
 * 首次启动桌面客户端时，将现有 MySQL 初始化脚本转换为 H2 兼容语法并执行。
 */
public final class DesktopDatabaseInitializer
{
    private static final Logger log = LoggerFactory.getLogger(DesktopDatabaseInitializer.class);
    private static final String[] SCRIPTS = {
        "db/mtd_20250417.sql", "db/quartz.sql", "db/en_traffic.sql"
    };
    private static final Pattern MYSQL_INDEX = Pattern.compile(
        "(?im)^\\s*(?:key|index)\\s+[^\\r\\n]+,?\\s*$");
    private static final Pattern MYSQL_TABLE_OPTIONS = Pattern.compile(
        "(?i)\\)\\s*engine\\s*=\\s*\\w+(?:\\s+auto_increment\\s*=\\s*\\d+)?(?:\\s+default\\s+charset\\s*=\\s*\\w+)?\\s+comment\\s*=\\s*'[^']*'\\s*;");

    private DesktopDatabaseInitializer()
    {
    }

    public static void initialize(DataSource dataSource)
    {
        try (Connection connection = dataSource.getConnection())
        {
            installCompatibilityFunctions(connection);
            if (isInitialized(connection))
            {
                log.info("桌面数据库已存在，跳过初始化");
                return;
            }

            log.info("首次运行，正在初始化桌面数据库");
            boolean autoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try
            {
                for (String script : SCRIPTS)
                {
                    execute(connection, script);
                }
                connection.commit();
                log.info("桌面数据库初始化完成");
            }
            catch (Exception exception)
            {
                connection.rollback();
                throw exception;
            }
            finally
            {
                connection.setAutoCommit(autoCommit);
            }
        }
        catch (Exception exception)
        {
            throw new IllegalStateException("无法初始化桌面数据库", exception);
        }
    }

    private static void installCompatibilityFunctions(Connection connection) throws SQLException
    {
        String className = DesktopDatabaseInitializer.class.getName();
        try (Statement statement = connection.createStatement())
        {
            statement.execute("CREATE ALIAS IF NOT EXISTS SYSDATE FOR \"" + className + ".sysdate\"");
            statement.execute("CREATE ALIAS IF NOT EXISTS DATE_FORMAT FOR \"" + className + ".dateFormat\"");
            statement.execute("CREATE ALIAS IF NOT EXISTS FIND_IN_SET FOR \"" + className + ".findInSet\"");
        }
    }

    /** H2 桌面模式使用的 MySQL 兼容函数。 */
    public static Timestamp sysdate()
    {
        return new Timestamp(System.currentTimeMillis());
    }

    public static String dateFormat(Timestamp value, String format)
    {
        if (value == null) return null;
        String javaFormat = format.replace("%Y", "yyyy").replace("%m", "MM").replace("%d", "dd");
        return value.toLocalDateTime().format(DateTimeFormatter.ofPattern(javaFormat));
    }

    public static int findInSet(String value, String csv)
    {
        if (value == null || csv == null) return 0;
        String[] items = csv.split(",");
        for (int index = 0; index < items.length; index++)
        {
            if (value.equals(items[index])) return index + 1;
        }
        return 0;
    }

    private static boolean isInitialized(Connection connection) throws SQLException
    {
        try (ResultSet tables = connection.getMetaData().getTables(null, null, "sys_user", new String[] { "TABLE" }))
        {
            return tables.next();
        }
    }

    private static void execute(Connection connection, String path) throws IOException, SQLException
    {
        ClassPathResource resource = new ClassPathResource(path);
        String sql = StreamUtils.copyToString(resource.getInputStream(), StandardCharsets.UTF_8);
        sql = MYSQL_INDEX.matcher(sql).replaceAll("");
        sql = MYSQL_TABLE_OPTIONS.matcher(sql).replaceAll(");");
        sql = sql.replaceAll("(?i)sysdate\\s*\\(\\s*\\)", "CURRENT_TIMESTAMP");
        sql = sql.replace("\\'", "''");
        sql = sql.replaceAll(",\\s*\\)", "\n)");
        ByteArrayResource converted = new ByteArrayResource(sql.getBytes(StandardCharsets.UTF_8), path);
        ScriptUtils.executeSqlScript(connection, new EncodedResource(converted, StandardCharsets.UTF_8));
    }
}
