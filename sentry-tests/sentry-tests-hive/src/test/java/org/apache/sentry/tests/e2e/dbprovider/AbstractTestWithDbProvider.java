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

package org.apache.sentry.tests.e2e.dbprovider;

import java.io.File;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import junit.framework.Assert;

import org.apache.commons.io.FileUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.conf.HiveConf.ConfVars;
import org.apache.sentry.binding.hive.SentryHiveAuthorizationTaskFactoryImpl;
import org.apache.sentry.provider.db.SimpleDBProviderBackend;
import org.apache.sentry.provider.file.PolicyFile;
import org.apache.sentry.service.thrift.SentryService;
import org.apache.sentry.service.thrift.SentryServiceFactory;
import org.apache.sentry.service.thrift.ServiceConstants.ClientConfig;
import org.apache.sentry.service.thrift.ServiceConstants.ServerConfig;
import org.apache.sentry.tests.e2e.hive.AbstractTestWithHiveServer;
import org.apache.sentry.tests.e2e.hive.Context;
import org.apache.sentry.tests.e2e.hive.StaticUserGroup;
import org.apache.sentry.tests.e2e.hive.hiveserver.HiveServerFactory;
import org.junit.After;
import org.junit.BeforeClass;

import com.google.common.collect.Maps;
import com.google.common.io.Files;

public abstract class AbstractTestWithDbProvider extends AbstractTestWithHiveServer {

  protected static final String SERVER_HOST = "localhost";

  private Map<String, String> properties;
  private File dbDir;
  private SentryService sentryServer;
  private Configuration conf;
  protected PolicyFile policyFile;

  @BeforeClass
  public static void setupTest() throws Exception {
  }

  public void setupSentryService() throws Exception {
    properties = Maps.newHashMap();
    conf = new Configuration(false);
    policyFile = new PolicyFile();

    properties.put(HiveServerFactory.AUTHZ_PROVIDER_BACKEND, SimpleDBProviderBackend.class.getName());
    properties.put(ConfVars.HIVE_AUTHORIZATION_TASK_FACTORY.varname,
        SentryHiveAuthorizationTaskFactoryImpl.class.getName());
    properties.put(ServerConfig.SECURITY_MODE, ServerConfig.SECURITY_MODE_NONE);
    properties.put(ServerConfig.ADMIN_GROUPS, ADMINGROUP);
    properties.put(ServerConfig.RPC_ADDRESS, SERVER_HOST);
    properties.put(ServerConfig.RPC_PORT, String.valueOf(0));
    properties.put(ServerConfig.SENTRY_VERIFY_SCHEM_VERSION, "false");
    dbDir = new File(Files.createTempDir(), "sentry_policy_db");
    properties.put(ServerConfig.SENTRY_STORE_JDBC_URL,
        "jdbc:derby:;databaseName=" + dbDir.getPath() + ";create=true");
    for (Map.Entry<String, String> entry : properties.entrySet()) {
      conf.set(entry.getKey(), entry.getValue());
    }
    sentryServer = new SentryServiceFactory().create(conf);
    properties.put(ClientConfig.SERVER_RPC_ADDRESS, sentryServer.getAddress().getHostString());
    properties.put(ClientConfig.SERVER_RPC_PORT,
        String.valueOf(sentryServer.getAddress().getPort()));
    startSentryService();
  }

  @After
  public void tearDown() throws Exception {
    if (sentryServer != null) {
      sentryServer.stop();
    }
    if (dbDir != null) {
      FileUtils.deleteQuietly(dbDir);
    }
  }

  public Context createContext() throws Exception {
    setupSentryService();
    Context context = createContext(properties);
    policyFile
    .setUserGroupMapping(StaticUserGroup.getStaticMapping())
    .write(context.getPolicyFile());
    return context;
  }

  protected void setupAdmin(Context context) throws Exception {
    Connection connection = context.createConnection(ADMIN1);
    Statement statement = connection.createStatement();
    statement.execute("CREATE ROLE admin_role");
    statement.execute("GRANT ALL ON SERVER "
        + HiveServerFactory.DEFAULT_AUTHZ_SERVER_NAME + " TO ROLE admin_role");
    statement.execute("GRANT ROLE admin_role TO GROUP " + ADMINGROUP);
    statement.close();
    connection.close();
  }

  protected void createDb(Connection connection, String...dbs) throws Exception {
    Statement statement = connection.createStatement();
    for(String db : dbs) {
      statement.execute("CREATE DATABASE " + db);
    }
    statement.close();
  }

  protected void createTable(Connection connection , String db, File dataFile, String...tables)
      throws Exception {
    Statement statement = connection.createStatement();
    statement.execute("USE " + db);
    for(String table : tables) {
      statement.execute("DROP TABLE IF EXISTS " + table);
      statement.execute("create table " + table
          + " (under_col int comment 'the under column', value string)");
      statement.execute("load data local inpath '" + dataFile.getPath()
          + "' into table " + table);
      ResultSet res = statement.executeQuery("select * from " + table);
      Assert.assertTrue("Table should have data after load", res.next());
      res.close();
    }
    statement.close();
  }

  private void startSentryService() throws Exception {
    sentryServer.start();
    final long start = System.currentTimeMillis();
    while(!sentryServer.isRunning()) {
      Thread.sleep(1000);
      if(System.currentTimeMillis() - start > 60000L) {
        throw new TimeoutException("Server did not start after 60 seconds");
      }
    }
  }

}