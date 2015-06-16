/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.sentry.tests.e2e.hive;

import static org.apache.sentry.provider.common.ProviderConstants.AUTHORIZABLE_SPLITTER;
import static org.apache.sentry.provider.common.ProviderConstants.PRIVILEGE_PREFIX;
import static org.apache.sentry.provider.common.ProviderConstants.ROLE_SPLITTER;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import junit.framework.Assert;

import org.apache.commons.io.FileUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.hive.conf.HiveConf.ConfVars;
import org.apache.sentry.binding.hive.v2.impl.SentryAuthorizationTaskFactoryImplV2;
import org.apache.sentry.binding.metastore.SentryMetastorePostEventListener;
import org.apache.sentry.core.model.db.DBModelAction;
import org.apache.sentry.core.model.db.DBModelAuthorizable;
import org.apache.sentry.policy.db.DBModelAuthorizables;
import org.apache.sentry.provider.db.SimpleDBProviderBackend;
import org.apache.sentry.provider.db.service.thrift.SentryPolicyServiceClient;
import org.apache.sentry.provider.file.PolicyFile;
import org.apache.sentry.service.thrift.SentryServiceClientFactory;
import org.apache.sentry.service.thrift.ServiceConstants.ClientConfig;
import org.apache.sentry.service.thrift.ServiceConstants.ServerConfig;
import org.apache.sentry.tests.e2e.hive.fs.DFS;
import org.apache.sentry.tests.e2e.hive.fs.DFSFactory;
import org.apache.sentry.tests.e2e.hive.hiveserver.HiveServer;
import org.apache.sentry.tests.e2e.hive.hiveserver.HiveServerFactory;
import org.apache.sentry.tests.e2e.minisentry.SentrySrv;
import org.apache.sentry.tests.e2e.minisentry.SentrySrvFactory;
import org.apache.sentry.tests.e2e.minisentry.SentrySrvFactory.SentrySrvType;
import org.apache.tools.ant.util.StringUtils;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Maps;
import com.google.common.io.Files;

public abstract class AbstractTestWithStaticConfiguration {
  private static final Logger LOGGER = LoggerFactory
      .getLogger(AbstractTestWithStaticConfiguration.class);
  protected static final String SINGLE_TYPE_DATA_FILE_NAME = "kv1.dat";
  protected static final String ALL_DB1 = "server=server1->db=db_1",
      ALL_DB2 = "server=server1->db=db_2",
      SELECT_DB1_TBL1 = "server=server1->db=db_1->table=tb_1->action=select",
      SELECT_DB1_TBL2 = "server=server1->db=db_1->table=tb_2->action=select",
      SELECT_DB1_NONTABLE = "server=server1->db=db_1->table=blahblah->action=select",
      INSERT_DB1_TBL1 = "server=server1->db=db_1->table=tb_1->action=insert",
      SELECT_DB2_TBL2 = "server=server1->db=db_2->table=tb_2->action=select",
      INSERT_DB2_TBL1 = "server=server1->db=db_2->table=tb_1->action=insert",
      SELECT_DB1_VIEW1 = "server=server1->db=db_1->table=view_1->action=select",
      ADMIN1 = StaticUserGroup.ADMIN1,
      ADMINGROUP = StaticUserGroup.ADMINGROUP,
      USER1_1 = StaticUserGroup.USER1_1,
      USER1_2 = StaticUserGroup.USER1_2,
      USER2_1 = StaticUserGroup.USER2_1,
      USER3_1 = StaticUserGroup.USER3_1,
      USER4_1 = StaticUserGroup.USER4_1,
      USERGROUP1 = StaticUserGroup.USERGROUP1,
      USERGROUP2 = StaticUserGroup.USERGROUP2,
      USERGROUP3 = StaticUserGroup.USERGROUP3,
      USERGROUP4 = StaticUserGroup.USERGROUP4,
      GROUP1_ROLE = "group1_role",
      DB1 = "db_1",
      DB2 = "db_2",
      DB3 = "db_3",
      TBL1 = "tb_1",
      TBL2 = "tb_2",
      TBL3 = "tb_3",
      VIEW1 = "view_1",
      VIEW2 = "view_2",
      VIEW3 = "view_3",
      INDEX1 = "index_1";

  protected static final String SERVER_HOST = "localhost";
  private static final String EXTERNAL_SENTRY_SERVICE = "sentry.e2etest.external.sentry";
  protected static final String EXTERNAL_HIVE_LIB = "sentry.e2etest.hive.lib";
  private static final String ENABLE_SENTRY_HA = "sentry.e2etest.enable.service.ha";

  protected static boolean policyOnHdfs = false;
  protected static boolean useSentryService = false;
  protected static boolean setMetastoreListener = false;
  protected static String testServerType = null;
  protected static boolean enableHiveConcurrency = false;
  // indicate if the database need to be clear for every test case in one test class
  protected static boolean clearDbAfterPerTest = true;

  protected static File baseDir;
  protected static File logDir;
  protected static File confDir;
  protected static File dataDir;
  protected static File policyFileLocation;
  protected static HiveServer hiveServer;
  protected static FileSystem fileSystem;
  protected static HiveServerFactory.HiveServer2Type hiveServer2Type;
  protected static DFS dfs;
  protected static Map<String, String> properties;
  protected static SentrySrv sentryServer;
  protected static Configuration sentryConf;
  protected static boolean enableSentryHA = false;
  protected static Context context;
  protected final String semanticException = "SemanticException No valid privileges";
  protected final String SENTRY_ACCESS_CONTROLLER_EXCEPTION = "SentryAccessControlException";

  public static void createContext() throws Exception {
    context = new Context(hiveServer, fileSystem,
        baseDir, confDir, dataDir, policyFileLocation);
  }
  protected void dropDb(String user, String...dbs) throws Exception {
    Connection connection = context.createConnection(user);
    Statement statement = connection.createStatement();
    for(String db : dbs) {
      statement.execute("DROP DATABASE IF EXISTS " + db + " CASCADE");
    }
    statement.close();
    connection.close();
  }
  protected void createDb(String user, String...dbs) throws Exception {
    Connection connection = context.createConnection(user);
    Statement statement = connection.createStatement();
    ArrayList<String> allowedDBs = new ArrayList<String>(Arrays.asList(DB1, DB2, DB3));
    for(String db : dbs) {
      assertTrue(db + " is not part of known test dbs which will be cleaned up after the test", allowedDBs.contains(db));
      statement.execute("CREATE DATABASE if not exists " + db);
    }
    statement.close();
    connection.close();
  }

  protected void createTable(String user, String db, File dataFile, String...tables)
      throws Exception {
    Connection connection = context.createConnection(user);
    Statement statement = connection.createStatement();
    statement.execute("USE " + db);
    for(String table : tables) {
      statement.execute("DROP TABLE IF EXISTS " + table);
      statement.execute("create table " + table
          + " (under_col int comment 'the under column', value string)");
      if(dataFile != null) {
        statement.execute("load data local inpath '" + dataFile.getPath()
            + "' into table " + table);
        ResultSet res = statement.executeQuery("select * from " + table);
        Assert.assertTrue("Table should have data after load", res.next());
        res.close();
      }
    }
    statement.close();
    connection.close();
  }

  protected static File assertCreateDir(File dir) {
    if(!dir.isDirectory()) {
      Assert.assertTrue("Failed creating " + dir, dir.mkdirs());
    }
    return dir;
  }

  @BeforeClass
  public static void setupTestStaticConfiguration() throws Exception {
    properties = Maps.newHashMap();
    if(!policyOnHdfs) {
      policyOnHdfs = new Boolean(System.getProperty("sentry.e2etest.policyonhdfs", "false"));
    }
    if (testServerType != null) {
      properties.put("sentry.e2etest.hiveServer2Type", testServerType);
    }
    baseDir = Files.createTempDir();
    LOGGER.info("BaseDir = " + baseDir);
    logDir = assertCreateDir(new File(baseDir, "log"));
    confDir = assertCreateDir(new File(baseDir, "etc"));
    dataDir = assertCreateDir(new File(baseDir, "data"));
    policyFileLocation = new File(confDir, HiveServerFactory.AUTHZ_PROVIDER_FILENAME);

    String dfsType = System.getProperty(DFSFactory.FS_TYPE);
    dfs = DFSFactory.create(dfsType, baseDir, testServerType);
    fileSystem = dfs.getFileSystem();

    PolicyFile policyFile = PolicyFile.setAdminOnServer1(ADMIN1)
        .setUserGroupMapping(StaticUserGroup.getStaticMapping());
    policyFile.write(policyFileLocation);

    String policyURI;
    if (policyOnHdfs) {
      String dfsUri = FileSystem.getDefaultUri(fileSystem.getConf()).toString();
      LOGGER.error("dfsUri " + dfsUri);
      policyURI = dfsUri + System.getProperty("sentry.e2etest.hive.policy.location",
          "/user/hive/sentry");
      policyURI += "/" + HiveServerFactory.AUTHZ_PROVIDER_FILENAME;
    } else {
      policyURI = policyFileLocation.getPath();
    }

    boolean startSentry = new Boolean(System.getProperty(EXTERNAL_SENTRY_SERVICE, "false"));
    if ("true".equalsIgnoreCase(System.getProperty(ENABLE_SENTRY_HA, "false"))) {
      enableSentryHA = true;
    }
    if (useSentryService && (!startSentry)) {
      setupSentryService();
    }

    if (enableHiveConcurrency) {
      properties.put(HiveConf.ConfVars.HIVE_SUPPORT_CONCURRENCY.varname, "true");
      properties.put(HiveConf.ConfVars.HIVE_TXN_MANAGER.varname,
          "org.apache.hadoop.hive.ql.lockmgr.DummyTxnManager");
      properties.put(HiveConf.ConfVars.HIVE_LOCK_MANAGER.varname,
          "org.apache.hadoop.hive.ql.lockmgr.EmbeddedLockManager");
    }

    hiveServer = create(properties, baseDir, confDir, logDir, policyURI, fileSystem);
    hiveServer.start();
    createContext();
  }

  public static HiveServer create(Map<String, String> properties,
      File baseDir, File confDir, File logDir, String policyFile,
      FileSystem fileSystem) throws Exception {
    String type = properties.get(HiveServerFactory.HIVESERVER2_TYPE);
    if(type == null) {
      type = System.getProperty(HiveServerFactory.HIVESERVER2_TYPE);
    }
    if(type == null) {
      type = HiveServerFactory.HiveServer2Type.InternalHiveServer2.name();
    }
    hiveServer2Type = HiveServerFactory.HiveServer2Type.valueOf(type.trim());
    return HiveServerFactory.create(hiveServer2Type, properties,
        baseDir, confDir, logDir, policyFile, fileSystem);
  }

  protected static void writePolicyFile(PolicyFile policyFile) throws Exception {
    policyFile.write(context.getPolicyFile());
    if(policyOnHdfs) {
      dfs.writePolicyFile(context.getPolicyFile());
    } else if(useSentryService) {
      grantPermissions(policyFile);
    }
  }

  private static void grantPermissions(PolicyFile policyFile) throws Exception {
    Connection connection = context.createConnection(ADMIN1);
    Statement statement = context.createStatement(connection);

    // remove existing metadata
    ResultSet resultSet = statement.executeQuery("SHOW ROLES");
    while( resultSet.next()) {
      Statement statement1 = context.createStatement(connection);
      if(!resultSet.getString(1).equalsIgnoreCase("admin_role")) {
        statement1.execute("DROP ROLE " + resultSet.getString(1));
      }
    }

    // create roles and add privileges
    for (Map.Entry<String, Collection<String>> roleEntry : policyFile.getRolesToPermissions()
        .asMap().entrySet()) {
      if(!roleEntry.getKey().equalsIgnoreCase("admin_role")){
        statement.execute("CREATE ROLE " + roleEntry.getKey());
        for (String privilege : roleEntry.getValue()) {
          addPrivilege(roleEntry.getKey(), privilege, statement);
        }
      }
    }
    // grant roles to groups
    for (Map.Entry<String, Collection<String>> groupEntry : policyFile.getGroupsToRoles().asMap()
        .entrySet()) {
      for (String roleNames : groupEntry.getValue()) {
        for (String roleName : roleNames.split(",")) {
          statement.execute("GRANT ROLE " + roleName + " TO GROUP " + groupEntry.getKey());
        }
      }
    }
  }

  private static void addPrivilege(String roleName, String privileges, Statement statement)
      throws IOException, SQLException{
    String serverName = null, dbName = null, tableName = null, uriPath = null, columnName = null;
    String action = "ALL";//AccessConstants.ALL;
    for (String privilege : ROLE_SPLITTER.split(privileges)) {
      for(String section : AUTHORIZABLE_SPLITTER.split(privilege)) {
        // action is not an authorizeable
        if(!section.toLowerCase().startsWith(PRIVILEGE_PREFIX)) {
          DBModelAuthorizable dbAuthorizable = DBModelAuthorizables.from(section);
          if(dbAuthorizable == null) {
            throw new IOException("Unknown Auth type " + section);
          }

          if (DBModelAuthorizable.AuthorizableType.Server.equals(dbAuthorizable.getAuthzType())) {
            serverName = dbAuthorizable.getName();
          } else if (DBModelAuthorizable.AuthorizableType.Db.equals(dbAuthorizable.getAuthzType())) {
            dbName = dbAuthorizable.getName();
          } else if (DBModelAuthorizable.AuthorizableType.Table.equals(dbAuthorizable.getAuthzType())) {
            tableName = dbAuthorizable.getName();
          } else if (DBModelAuthorizable.AuthorizableType.Column.equals(dbAuthorizable.getAuthzType())) {
            columnName = dbAuthorizable.getName();
          } else if (DBModelAuthorizable.AuthorizableType.URI.equals(dbAuthorizable.getAuthzType())) {
            uriPath = dbAuthorizable.getName();
          } else {
            throw new IOException("Unsupported auth type " + dbAuthorizable.getName()
                + " : " + dbAuthorizable.getTypeName());
          }
        } else {
          action = DBModelAction.valueOf(
              StringUtils.removePrefix(section, PRIVILEGE_PREFIX).toUpperCase())
              .toString();
        }
      }

      if (columnName != null) {
        statement.execute("CREATE DATABASE IF NOT EXISTS " + dbName);
        statement.execute("USE " + dbName);
        statement.execute("CREATE TABLE IF NOT EXISTS " + tableName + " ( " + columnName + " string) ");
        statement.execute("GRANT " + action + " ( " + columnName + " ) ON TABLE " + tableName + " TO ROLE " + roleName);
      } else if (tableName != null) {
        statement.execute("CREATE DATABASE IF NOT EXISTS " + dbName);
        statement.execute("USE " + dbName);
        statement.execute("CREATE TABLE IF NOT EXISTS " + tableName + " (c1 string) ");
        statement.execute("GRANT " + action + " ON TABLE " + tableName + " TO ROLE " + roleName);
      } else if (dbName != null) {
        statement.execute("CREATE TABLE IF NOT EXISTS " + tableName + " (c1 string) ");
        statement.execute("GRANT " + action + " ON DATABASE " + dbName + " TO ROLE " + roleName);
      } else if (uriPath != null) {
        statement.execute("GRANT " + action + " ON URI '" + uriPath + "' TO ROLE " + roleName);//ALL?
      } else if (serverName != null) {
        statement.execute("GRANT ALL ON SERVER " + serverName + " TO ROLE " + roleName);
        ;
      }
    }
  }

  private static void setupSentryService() throws Exception {

    sentryConf = new Configuration(false);

    properties.put(HiveServerFactory.AUTHZ_PROVIDER_BACKEND,
        SimpleDBProviderBackend.class.getName());
    properties.put(ConfVars.HIVE_AUTHORIZATION_TASK_FACTORY.varname,
        SentryAuthorizationTaskFactoryImplV2.class.getName());
    properties
    .put(ConfVars.HIVE_SERVER2_THRIFT_MIN_WORKER_THREADS.varname, "2");
    properties.put(ServerConfig.SECURITY_MODE, ServerConfig.SECURITY_MODE_NONE);
    properties.put(ServerConfig.ADMIN_GROUPS, ADMINGROUP);
    properties.put(ServerConfig.RPC_ADDRESS, SERVER_HOST);
    properties.put(ServerConfig.RPC_PORT, String.valueOf(0));
    properties.put(ServerConfig.SENTRY_VERIFY_SCHEM_VERSION, "false");

    properties.put(ServerConfig.SENTRY_STORE_JDBC_URL,
        "jdbc:derby:;databaseName=" + baseDir.getPath()
        + "/sentrystore_db;create=true");
    properties.put(ServerConfig.SENTRY_STORE_GROUP_MAPPING, ServerConfig.SENTRY_STORE_LOCAL_GROUP_MAPPING);
    properties.put(ServerConfig.SENTRY_STORE_GROUP_MAPPING_RESOURCE, policyFileLocation.getPath());
    properties.put(ServerConfig.RPC_MIN_THREADS, "3");
    for (Map.Entry<String, String> entry : properties.entrySet()) {
      sentryConf.set(entry.getKey(), entry.getValue());
    }
    sentryServer = SentrySrvFactory.create(
        SentrySrvType.INTERNAL_SERVER, sentryConf, enableSentryHA ? 2 : 1);
    properties.put(ClientConfig.SERVER_RPC_ADDRESS, sentryServer.get(0)
        .getAddress()
        .getHostName());
    sentryConf.set(ClientConfig.SERVER_RPC_ADDRESS, sentryServer.get(0)
        .getAddress()
        .getHostName());
    properties.put(ClientConfig.SERVER_RPC_PORT,
        String.valueOf(sentryServer.get(0).getAddress().getPort()));
    sentryConf.set(ClientConfig.SERVER_RPC_PORT,
        String.valueOf(sentryServer.get(0).getAddress().getPort()));
    if (enableSentryHA) {
      properties.put(ClientConfig.SERVER_HA_ENABLED, "true");
      properties.put(ClientConfig.SENTRY_HA_ZOOKEEPER_QUORUM,
          sentryServer.getZKQuorum());
    }
    startSentryService();
    if (setMetastoreListener) {
      properties.put(HiveConf.ConfVars.METASTORE_EVENT_LISTENERS.varname,
          SentryMetastorePostEventListener.class.getName());
    }

  }

  private static void startSentryService() throws Exception {
    sentryServer.startAll();
  }

  public static SentryPolicyServiceClient getSentryClient() throws Exception {
    if (sentryServer == null) {
      throw new IllegalAccessException("Sentry service not initialized");
    }
    return SentryServiceClientFactory.create(sentryServer.get(0).getConf());
  }

  @Before
  public void setup() throws Exception{
    dfs.createBaseDir();
  }

  @After
  public void clearDB() throws Exception {
    ResultSet resultSet;
    Connection connection = context.createConnection(ADMIN1);
    Statement statement = context.createStatement(connection);

    if (clearDbAfterPerTest) {
      String[] dbs = { DB1, DB2, DB3 };
      for (String db : dbs) {
        statement.execute("DROP DATABASE if exists " + db + " CASCADE");
      }
      statement.execute("USE default");
      resultSet = statement.executeQuery("SHOW tables");
      while (resultSet.next()) {
        Statement statement2 = context.createStatement(connection);
        statement2.execute("DROP table " + resultSet.getString(1));
        statement2.close();
      }
    }

    if(useSentryService) {
      resultSet = statement.executeQuery("SHOW roles");
      List<String> roles = new ArrayList<String>();
      while (resultSet.next()) {
        roles.add(resultSet.getString(1));
      }
      for (String role : roles) {
        statement.execute("DROP Role " + role);
      }
    }
    statement.close();
    connection.close();

  }

  protected static void setupAdmin() throws Exception {
    if(useSentryService) {
      Connection connection = context.createConnection(ADMIN1);
      Statement statement = connection.createStatement();
      try {
        statement.execute("CREATE ROLE admin_role");
      } catch ( Exception e) {
        //It is ok if admin_role already exists
      }
      statement.execute("GRANT ALL ON SERVER "
          + HiveServerFactory.DEFAULT_AUTHZ_SERVER_NAME + " TO ROLE admin_role");
      statement.execute("GRANT ROLE admin_role TO GROUP " + ADMINGROUP);
      statement.close();
      connection.close();
    }
  }

  @AfterClass
  public static void tearDownTestStaticConfiguration() throws Exception {
    if(hiveServer != null) {
      hiveServer.shutdown();
      hiveServer = null;
    }

    if (sentryServer != null) {
      sentryServer.close();
      sentryServer = null;
    }

    if(baseDir != null) {
      if(System.getProperty(HiveServerFactory.KEEP_BASEDIR) == null) {
        FileUtils.deleteQuietly(baseDir);
      }
      baseDir = null;
    }
    if(dfs != null) {
      try {
        dfs.tearDown();
      } catch (Exception e) {
        LOGGER.info("Exception shutting down dfs", e);
      }
    }
    if (context != null) {
      context.close();
    }
  }

  public static SentrySrv getSentrySrv() {
    return sentryServer;
  }
}
