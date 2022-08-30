package com.webank.ai.fate.serving.adaptor.dataaccess;

import com.clickhouse.jdbc.ClickHouseDataSource;
import com.webank.ai.fate.serving.core.bean.BatchHostFeatureAdaptorResult;
import com.webank.ai.fate.serving.core.bean.BatchHostFederatedParams;
import com.webank.ai.fate.serving.core.bean.Context;
import com.webank.ai.fate.serving.core.constant.StatusCode;
import com.webank.ai.fate.serving.core.utils.JsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class CustomBatchAdapter extends AbstractBatchFeatureDataAdaptor {
    private static final Logger logger = LoggerFactory.getLogger(CustomBatchAdapter.class);

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
    public BatchHostFeatureAdaptorResult getFeatures(Context context, List<BatchHostFederatedParams.SingleInferenceData> featureIdList) {
        BatchHostFeatureAdaptorResult batchHostFeatureAdaptorResult = new BatchHostFeatureAdaptorResult();

        try (Connection conn = this.dataSource.getConnection(this.username, this.password)) {
            featureIdList.forEach(singleInferenceData -> {
                Map<Integer, BatchHostFeatureAdaptorResult.SingleBatchHostFeatureAdaptorResult> indexMap = batchHostFeatureAdaptorResult.getIndexResultMap();
                BatchHostFeatureAdaptorResult.SingleBatchHostFeatureAdaptorResult singleBatchHostFeatureAdaptorResult = new BatchHostFeatureAdaptorResult.SingleBatchHostFeatureAdaptorResult();

                Map<String, Object> featureIds = singleInferenceData.getSendToRemoteFeatureData();
                String object2Json = JsonUtil.object2Json(featureIds.get(this.partyId));
                if (object2Json == null || object2Json.isEmpty()) {
                    logger.error("party id {} has no features", this.partyId);
                    singleBatchHostFeatureAdaptorResult.setRetcode(StatusCode.HOST_PARAM_ERROR);
                    indexMap.put(singleInferenceData.getIndex(), singleBatchHostFeatureAdaptorResult);
                } else {
                    Map featureId = JsonUtil.json2Object(object2Json, Map.class);
                    String database = featureId.getOrDefault("database", "").toString();
                    String table = featureId.getOrDefault("table", "").toString();
                    String id = featureId.getOrDefault("id", "").toString();
                    if (database.isEmpty() || table.isEmpty() || id.isEmpty()) {
                        logger.error("database, table and id could not be empty");
                        singleBatchHostFeatureAdaptorResult.setRetcode(StatusCode.HOST_PARAM_ERROR);
                        indexMap.put(singleInferenceData.getIndex(), singleBatchHostFeatureAdaptorResult);
                    } else {
                        logger.info("database: {}, table: {}, id: {}", database, table, id);
                        Map<String, Object> data = new HashMap<>();
                        try (PreparedStatement stmt = conn.prepareStatement("SELECT * FROM " + database + "." + table + " WHERE id = ?")) {
                            stmt.setString(1, id);
                            ResultSet rs = stmt.executeQuery();

                            if (!rs.next()) {
                                logger.error("{}.{} has no id:{}", database, table, id);
                                singleBatchHostFeatureAdaptorResult.setRetcode(StatusCode.HOST_PARAM_ERROR);
                                indexMap.put(singleInferenceData.getIndex(), singleBatchHostFeatureAdaptorResult);
                            }

                            ResultSetMetaData rsmd = rs.getMetaData();
                            for (int i = 1; i <= rsmd.getColumnCount(); i++) {
                                String col = rsmd.getColumnName(i);
                                data.put(col, rs.getString(col));
                                logger.debug("{}:{}", col, rs.getString(col));
                            }

                            singleBatchHostFeatureAdaptorResult.setFeatures(data);
                            singleBatchHostFeatureAdaptorResult.setRetcode(StatusCode.SUCCESS);
                        } catch (Exception ex) {
                            logger.error(ex.getMessage());
                            singleBatchHostFeatureAdaptorResult.setRetcode(StatusCode.SYSTEM_ERROR);
                        }
                        indexMap.put(singleInferenceData.getIndex(), singleBatchHostFeatureAdaptorResult);
                    }
                }
            });
        } catch (Exception ex) {
            logger.error(ex.getMessage());
            batchHostFeatureAdaptorResult.setRetcode(StatusCode.SYSTEM_ERROR);
            return batchHostFeatureAdaptorResult;
        }

        batchHostFeatureAdaptorResult.setRetcode(StatusCode.SUCCESS);
        return batchHostFeatureAdaptorResult;
    }
}
