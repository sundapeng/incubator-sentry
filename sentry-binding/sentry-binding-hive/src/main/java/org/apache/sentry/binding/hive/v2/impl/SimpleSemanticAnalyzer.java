/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.sentry.binding.hive.v2.impl;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.hadoop.hive.ql.plan.HiveOperation;
import org.apache.hadoop.hive.ql.session.SessionState;
import org.apache.sentry.binding.hive.v2.util.SentryAccessControlException;

/**
 * Currently hive complier doesn't create read/write entityes for some operations,
 * e.g. create table, drop table.
 * This class is a simple semantic analyzer using regex,
 * it is a workaround approach to extract dbname and tbname from those operations.
 *
 */
public class SimpleSemanticAnalyzer {
  private String currentDb;
  private String currentTb;

  /**
   * CREATE [TEMPORARY] [EXTERNAL] TABLE [IF NOT EXISTS] [db_name.]table_name ...
   */
  private static final String CREATE_TABLE_REGEX =
      "^(CREATE)\\s+" +
      "(TEMPORARY\\s+)?" +
      "(EXTERNAL\\s+)?" +
      "TABLE\\s+" +
      "(IF\\s+NOT\\s+EXISTS\\s+)?" +
      "([A-Za-z0-9._]+)";

  /**
   * DROP (DATABASE|SCHEMA) [IF EXISTS] database_name [RESTRICT|CASCADE];
   */
  private static final String DROP_DB_REGEX =
      "^DROP\\s+" +
      "(DATABASE|SCHEMA)\\s+" +
      "(IF\\s+EXISTS\\s+)?" +
      "([A-Za-z0-9_]+)";

  /**
   * DROP TABLE [IF EXISTS] table_name;
   */
  private static final String DROP_TABLE_REGEX =
      "^DROP\\s+" +
      "TABLE\\s+" +
      "(IF\\s+EXISTS\\s+)?" +
      "([A-Za-z0-9._]+)";

  /**
   * DROP VIEW [IF EXISTS] view_name;
   */
  private static final String DROP_VIEW_REGEX =
      "^DROP\\s+" +
      "VIEW\\s+" +
      "(IF\\s+EXISTS\\s+)?" +
      "([A-Za-z0-9_].+)";

  /**
   * DESCRIBE DATABASE|SCHEMA [EXTENDED] db_name;
   */
  private static final String DESCRIBE_DB_REGEX =
      "^DESCRIBE\\s+" +
      "(DATABASE|SCHEMA)\\s+" +
      "(EXTENDED\\s+)?" +
      "([A-Za-z0-9_]+)";

  /**
   * DESCRIBE [EXTENDED|FORMATTED]
   *   [db_name.]table_name[.col_name ( [.field_name] | [.'$elem$'] | [.'$key$'] | [.'$value$'] )* ];
   */
  private static final String DESCRIBE_TABLE_REGEX =
      "^DESCRIBE\\s+" +
      "((EXTENDED|FORMATTED)\\s+)?" +
      "([A-Za-z0-9._]+)";

  /**
   * SHOW [FORMATTED] (INDEX|INDEXES) ON table_with_index [(FROM|IN) db_name];
   */
  private static final String SHOW_INDEX_REGEX =
      "^SHOW\\s+" +
      "(FORMATTED\\s+)?" +
      "(INDEX|INDEXES)\\s+" +
      "ON\\s+" +
      "([A-Za-z0-9._]+)\\s*" +
      "((FROM|IN)\\s+([A-Za-z0-9_]+))?";

  /**
   * SHOW TBLPROPERTIES tblname;
   */
  private static final String SHOW_TBLPROPERTIES_REGEX =
      "^SHOW\\s+" +
      "TBLPROPERTIES\\s+" +
      "([A-Za-z0-9._]+)";

  /**
   * ALTER TABLE table_name ...
   */
  private static final String ALTER_TABLE_REGEX =
      "^ALTER\\s+" +
      "TABLE\\s+" +
      "([A-Za-z0-9._]+)";

  /**
   * ALTER VIEW view_name ...
   */
  private static final String ALTER_VIEW_REGEX =
      "^ALTER\\s+" +
      "VIEW\\s+" +
      "([A-Za-z0-9._]+)";

  /**
   * MSCK REPAIR TABLE table_name;
   */
  private static final String MSCK_REGEX =
      "^MSCK\\s+" +
      "REPAIR\\s" +
      "TABLE\\s" +
      "([A-Za-z0-9._]+)";

  /**
   * ALTER INDEX index_name ON table_name [PARTITION partition_spec] REBUILD;
   */
  private static final String ALTER_INDEX_REGEX =
      "^ALTER\\s+" +
      "INDEX\\s+" +
      "([A-Za-z0-9_]+)\\s+" +
      "ON\\s" +
      "([A-Za-z0-9._]+)";

  /**
   * CREATE FUNCTION [db_name.]function_name AS class_name
   *   [USING JAR|FILE|ARCHIVE 'file_uri' [, JAR|FILE|ARCHIVE 'file_uri'] ];
   */
  private static final String CREATE_FUNCTION_REGEX =
      "^CREATE\\s+" +
      "(TEMPORARY\\s+)?" +
      "FUNCTION\\s+" +
      "([A-Za-z0-9._]+)\\s+" +
      "AS\\s" +
      "([A-Za-z0-9._']+)";

  private static Map<HiveOperation, String> OP_REGEX_MAP = new HashMap<HiveOperation, String>();
  static {
    // database metadata
    OP_REGEX_MAP.put(HiveOperation.DROPDATABASE, DROP_DB_REGEX);
    OP_REGEX_MAP.put(HiveOperation.DESCDATABASE, DESCRIBE_DB_REGEX);

    // tabale metadata
    OP_REGEX_MAP.put(HiveOperation.CREATETABLE, CREATE_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.DROPTABLE, DROP_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.DROPVIEW, DROP_VIEW_REGEX);
    OP_REGEX_MAP.put(HiveOperation.DESCTABLE, DESCRIBE_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.SHOW_TBLPROPERTIES, SHOW_TBLPROPERTIES_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_PROPERTIES, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_SERDEPROPERTIES, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_CLUSTER_SORT, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_FILEFORMAT, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_TOUCH, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_PROTECTMODE, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_RENAMECOL, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_ADDCOLS, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_REPLACECOLS, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_RENAMEPART, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_ARCHIVE, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_UNARCHIVE, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_SERIALIZER, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_MERGEFILES, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_SKEWED, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_DROPPARTS, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_ADDPARTS, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_RENAME, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTABLE_LOCATION, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERPARTITION_FILEFORMAT, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERPARTITION_PROTECTMODE, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERPARTITION_SERDEPROPERTIES, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERPARTITION_SERIALIZER, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERPARTITION_MERGEFILES, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERPARTITION_LOCATION, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERTBLPART_SKEWED_LOCATION, ALTER_TABLE_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERVIEW_PROPERTIES, ALTER_VIEW_REGEX);
    OP_REGEX_MAP.put(HiveOperation.MSCK, MSCK_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERINDEX_REBUILD, ALTER_INDEX_REGEX);
    OP_REGEX_MAP.put(HiveOperation.ALTERINDEX_PROPS, ALTER_INDEX_REGEX);
  }

  public SimpleSemanticAnalyzer(HiveOperation hiveOp, String cmd) throws SentryAccessControlException {
    currentDb = SessionState.get().getCurrentDatabase();
    parse(hiveOp, cmd);
  }

  private void parse(HiveOperation hiveOp, String cmd) throws SentryAccessControlException {
    switch (hiveOp) {
      case DROPDATABASE:
      case DESCDATABASE:
        parseDbMeta(cmd, OP_REGEX_MAP.get(hiveOp));
        break;
      case DESCTABLE:
      case CREATETABLE:
      case DROPTABLE:
      case DROPVIEW:
      case SHOW_TBLPROPERTIES:
        // alter table
      case ALTERTABLE_PROPERTIES:
      case ALTERTABLE_SERDEPROPERTIES:
      case ALTERTABLE_CLUSTER_SORT:
      case ALTERTABLE_FILEFORMAT:
      case ALTERTABLE_TOUCH:
      case ALTERTABLE_PROTECTMODE:
      case ALTERTABLE_RENAMECOL:
      case ALTERTABLE_ADDCOLS:
      case ALTERTABLE_REPLACECOLS:
      case ALTERTABLE_RENAMEPART:
      case ALTERTABLE_ARCHIVE:
      case ALTERTABLE_UNARCHIVE:
      case ALTERTABLE_SERIALIZER:
      case ALTERTABLE_MERGEFILES:
      case ALTERTABLE_SKEWED:
      case ALTERTABLE_DROPPARTS:
      case ALTERTABLE_ADDPARTS:
      case ALTERTABLE_RENAME:
      case ALTERTABLE_LOCATION:
        // alter view
      case ALTERVIEW_PROPERTIES:
        // alter partition
      case ALTERPARTITION_FILEFORMAT:
      case ALTERPARTITION_PROTECTMODE:
      case ALTERPARTITION_SERDEPROPERTIES:
      case ALTERPARTITION_SERIALIZER:
      case ALTERPARTITION_MERGEFILES:
      case ALTERPARTITION_LOCATION:
      case ALTERTBLPART_SKEWED_LOCATION:
        // MSCK
      case MSCK:
        // alter index
      case ALTERINDEX_REBUILD:
      case ALTERINDEX_PROPS:
        parseTableMeta(cmd, OP_REGEX_MAP.get(hiveOp));
        break;
      case SHOWINDEXES:
        parseShowIndex(cmd, SHOW_INDEX_REGEX);
        break;
      case CREATEFUNCTION:
        parseFunction(cmd, CREATE_FUNCTION_REGEX);
        break;
      default:
        break;
    }
  }

  private void extractDbAndTb(String tableName) {
    if (tableName.contains(".")) {
      String[] tb = tableName.split("\\.");
      currentDb = tb[0];
      currentTb = tb[1];
    } else {
      currentDb = SessionState.get().getCurrentDatabase();
      currentTb = tableName;
    }
  }

  private void parseDbMeta(String cmd, String regex) throws SentryAccessControlException {
    Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    Matcher matcher = pattern.matcher(cmd);
    if (matcher.find()) {
      currentDb = matcher.group(matcher.groupCount());
    } else {
      throw new SentryAccessControlException("this command " +
          cmd + " is not match database meta grammar");
    }
  }

  private void parseTableMeta(String cmd, String regex) throws SentryAccessControlException {
    Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    Matcher matcher = pattern.matcher(cmd);
    if (matcher.find()) {
      String tbName = matcher.group(matcher.groupCount());
      extractDbAndTb(tbName.trim());
    } else {
      throw new SentryAccessControlException("this command " +
          cmd + " is not match table meta grammar");
    }
  }

  private void parseShowIndex(String cmd, String regex) throws SentryAccessControlException {
    Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    Matcher matcher = pattern.matcher(cmd);
    if (matcher.find()) {
      String dbName = matcher.group(matcher.groupCount());
      String tbName = matcher.group(3);
      if (dbName != null) {
        currentDb = dbName;
        currentTb = tbName;
      } else {
        extractDbAndTb(tbName);
      }
    } else {
      throw new SentryAccessControlException("this command " +
          cmd + " is not match show index grammar");
    }
  }

  private void parseFunction(String cmd, String regex) throws SentryAccessControlException {
    Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    Matcher matcher = pattern.matcher(cmd);
    if (matcher.find()) {
      String udfClass = matcher.group(matcher.groupCount());
      if (udfClass.contains("'")) {
        currentTb = udfClass.split("'")[1];
      } else {
        currentTb = udfClass;
      }
    } else {
      throw new SentryAccessControlException("this command " +
          cmd + " is not match create function grammar");
    }
  }

  public String getCurrentDb() {
    return currentDb;
  }

  public String getCurrentTb() {
    return currentTb;
  }

}
