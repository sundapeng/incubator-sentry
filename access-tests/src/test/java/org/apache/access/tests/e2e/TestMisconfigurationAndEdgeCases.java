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

package org.apache.access.tests.e2e;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileOutputStream;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.google.common.base.Charsets;
import com.google.common.collect.Maps;

public class TestMisconfigurationAndEdgeCases {

  private EndToEndTestContext context;
  private Map<String, String> properties;
  @Before
  public void setup() throws Exception {
    properties = Maps.newHashMap();
  }

  @After
  public void tearDown() throws Exception {
    if(context != null) {
      context.close();
    }
  }

  /**
   * hive.server2.enable.impersonation must be disabled
   */
  @Test
  public void testImpersonationIsDisabled() throws Exception {
    properties.put("hive.server2.enable.impersonation", "true");
    context = new EndToEndTestContext(false, properties);
    Connection connection = context.createConnection("TODO", "TODO");
    Statement statement = context.createStatement(connection);
    try {
      statement.execute("create table test (a string)");
      Assert.fail("Expected SQLException");
    } catch (SQLException e) {
      assertEquals("TODO", e.getSQLState());
    }
  }

  /**
   * hive.server2.enable.impersonation must be set to LDAP or KERBEROS
   */
  @Test
  public void testAuthenticationIsStrong() throws Exception {
    properties.put("hive.server2.enable.impersonation", "NONE");
    context = new EndToEndTestContext(false, properties);
    Connection connection = context.createConnection("TODO", "TODO");
    Statement statement = context.createStatement(connection);
    try {
      statement.execute("create table test (a string)");
      Assert.fail("Expected SQLException");
    } catch (SQLException e) {
      assertEquals("TODO", e.getSQLState());
    }
  }

  /**
   * Test removal of policy file
   */
  @Test
  public void testRemovalOfPolicyFile() throws Exception {
    context = new EndToEndTestContext(false, properties);
    File policyFile = context.getPolicyFile();
    assertTrue("Could not delete " + policyFile, policyFile.delete());
    Connection connection = context.createConnection("TODO", "TODO");
    Statement statement = context.createStatement(connection);
    try {
      statement.execute("create table test (a string)");
      Assert.fail("Expected SQLException");
    } catch (SQLException e) {
      assertEquals("TODO", e.getSQLState());
    }
  }

  /**
   * Test corruption of policy file
   */
  @Test
  public void testCorruptionOfPolicyFile() throws Exception {
    context = new EndToEndTestContext(false, properties);
    File policyFile = context.getPolicyFile();
    assertTrue("Could not delete " + policyFile, policyFile.delete());
    FileOutputStream out = new FileOutputStream(policyFile);
    out.write("this is not valid".getBytes(Charsets.UTF_8));
    out.close();
    Connection connection = context.createConnection("TODO", "TODO");
    Statement statement = context.createStatement(connection);
    try {
      statement.execute("create table test (a string)");
      Assert.fail("Expected SQLException");
    } catch (SQLException e) {
      assertEquals("TODO", e.getSQLState());
    }
  }

  /**
   * Test removing user after compilation before access check
   * results in user not being authorized
   */
  @Test
  public void testUserRemovalBeforeAccessCheckAfterCompile() throws Exception {
    properties.put(EndToEndTestContext.AUTHZ_PROVIDER, SlowLocalGroupResourceAuthorizationProvider.class.getName());
    context = new EndToEndTestContext(false, properties);
    File policyFile = context.getPolicyFile();
    fail("TODO remove user from policy file, waiting on changed to Utils");
    Connection connection = context.createConnection("TODO", "TODO");
    Statement statement = context.createStatement(connection);
    try {
      statement.execute("create table test (a string)");
      Assert.fail("Expected SQLException");
    } catch (SQLException e) {
      assertEquals("TODO", e.getSQLState());
    }
  }

  /**
   * Test adding user after compilation before access check
   * results in user being authorized
   */
  @Test
  public void testUserAdditionBeforeAccessCheckAfterCompile() throws Exception {
    properties.put(EndToEndTestContext.AUTHZ_PROVIDER, SlowLocalGroupResourceAuthorizationProvider.class.getName());
    context = new EndToEndTestContext(false, properties);
    File policyFile = context.getPolicyFile();
    fail("TODO add user from policy file, waiting on changed to Utils");
    Connection connection = context.createConnection("TODO", "TODO");
    Statement statement = context.createStatement(connection);
    try {
      statement.execute("create table test (a string)");
      Assert.fail("Expected SQLException");
    } catch (SQLException e) {
      assertEquals("TODO", e.getSQLState());
    }
  }


  /**
   * This test never fails and when the policy file is not correct.
   * Therefore I am leaving it to make sure sure we figure out what
   * is wrong later. Then this can be moved to a different file or
   * removed if there is a duplicate test.
   */
  @Test
  public void testAuthorizationFailure() throws Exception {
    context = new EndToEndTestContext(false, properties);
    Connection connection = context.createConnection("TODO", "TODO");
    Statement statement = context.createStatement(connection);
    try {
      statement.execute("create table test (a string)");
      Assert.fail("Expected SQLException");
    } catch (SQLException e) {
      assertEquals("TODO", e.getSQLState());
    }
  }
}