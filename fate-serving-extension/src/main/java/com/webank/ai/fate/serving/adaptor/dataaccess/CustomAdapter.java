package com.webank.ai.fate.serving.adaptor.dataaccess;

import com.clickhouse.jdbc.ClickHouseDataSource;
import com.webank.ai.fate.serving.core.bean.Context;
import com.webank.ai.fate.serving.core.bean.ReturnResult;
import com.webank.ai.fate.serving.core.constant.StatusCode;
import com.webank.ai.fate.serving.core.utils.JsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class CustomAdapter extends AbstractSingleFeatureDataAdaptor {
    private static final Logger logger = LoggerFactory.getLogger(CustomAdapter.class);

    private String partyId = "";
    private ClickHouseDataSource dataSource = null;
    private String username = "";
    private String password = "";

    @Override
    public void init() {
        this.partyId = environment.getProperty("party.id");
        String url = environment.getProperty("clickhouse.url");
        this.username = environment.getProperty("clickhouse.username");
        this.password = environment.getProperty("clickhouse.password");
        Properties properties = new Properties();
        try {
            this.dataSource = new ClickHouseDataSource(url, properties);
        } catch (Exception ex) {
            logger.error(ex.getMessage());
        }
    }

    @Override
    public ReturnResult getData(Context context, Map<String, Object> featureIds) {
        ReturnResult returnResult = new ReturnResult();
        String object2Json = JsonUtil.object2Json(featureIds.get(this.partyId));
        if (object2Json == null || object2Json.isEmpty()) {
            logger.error("party id {} has no features", this.partyId);
            returnResult.setRetcode(StatusCode.HOST_PARAM_ERROR);
            return returnResult;
        }

        Map featureId = JsonUtil.json2Object(object2Json, Map.class);
        String database = featureId.getOrDefault("database", "").toString();
        String table = featureId.getOrDefault("table", "").toString();
        String id = featureId.getOrDefault("id", "").toString();
        if (database.isEmpty() || table.isEmpty() || id.isEmpty()) {
            logger.error("database, table and id could not be empty");
            returnResult.setRetcode(StatusCode.HOST_PARAM_ERROR);
            return returnResult;
        }
        logger.info("partyId: {}, database: {}, table: {}, id: {}", this.partyId, database, table, id);

        Map<String, Object> data = new HashMap<>();
        try (Connection conn = dataSource.getConnection(this.username, this.password)) {
            PreparedStatement stmt = conn.prepareStatement("SELECT * FROM " + database + "." + table + " WHERE id = ?");
            stmt.setString(1, id);
            ResultSet rs = stmt.executeQuery();

            if (!rs.next()) {
                logger.error("{}.{} has no id:{}", database, table, id);
                returnResult.setRetcode(StatusCode.HOST_PARAM_ERROR);
                return returnResult;
            }
            ResultSetMetaData rsmd = rs.getMetaData();
            for (int i = 1; i <= rsmd.getColumnCount(); i++) {
                String col = rsmd.getColumnName(i);
                data.put(col, rs.getString(col));
                logger.debug("{}:{}", col, rs.getString(col));
            }

            returnResult.setData(data);
            returnResult.setRetcode(StatusCode.SUCCESS);
        } catch (Exception ex) {
            logger.error(ex.getMessage());
            returnResult.setRetcode(StatusCode.SYSTEM_ERROR);
        }
        return returnResult;
    }
}
