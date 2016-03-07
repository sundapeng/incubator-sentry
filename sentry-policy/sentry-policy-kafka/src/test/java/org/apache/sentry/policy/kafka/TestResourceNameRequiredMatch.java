/*
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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sentry.policy.kafka;

import junit.framework.Assert;

import org.apache.sentry.policy.common.PrivilegeValidatorContext;
import org.apache.sentry.policy.kafka.ResourceRequiredMatch;
import org.apache.shiro.config.ConfigurationException;
import org.junit.Test;

public class TestResourceNameRequiredMatch {
  @Test
  public void testWithoutResourceName() {
    ResourceRequiredMatch serverNameMatch = new ResourceRequiredMatch();
    try {
      serverNameMatch.validate(new PrivilegeValidatorContext("server=server1"));
    } catch (ConfigurationException ex) {
      Assert.fail("Not expected ConfigurationException");
    }
  }

  @Test
  public void testWithoutServerName() throws Exception {
    ResourceRequiredMatch serverNameMatch = new ResourceRequiredMatch();
    try {
      serverNameMatch.validate(new PrivilegeValidatorContext("connector=c1->action=read"));
      Assert.fail("Expected ConfigurationException");
    } catch (ConfigurationException ex) {
    }
    try {
      serverNameMatch.validate(new PrivilegeValidatorContext("topic=t1->action=read"));
      Assert.fail("Expected ConfigurationException");
    } catch (ConfigurationException ex) {
    }
    try {
      serverNameMatch.validate(new PrivilegeValidatorContext("consumer_group=g1->action=read"));
      Assert.fail("Expected ConfigurationException");
    } catch (ConfigurationException ex) {
    }
  }
  @Test
  public void testServerNameMatch() throws Exception {
    ResourceRequiredMatch serverNameMatch = new ResourceRequiredMatch();
    try {
      serverNameMatch.validate(new PrivilegeValidatorContext("server=server1->cluster=c1->action=read"));
    } catch (ConfigurationException ex) {
      Assert.fail("Not expected ConfigurationException");
    }
    try {
      serverNameMatch.validate(new PrivilegeValidatorContext("server=server1->topic=t1->action=read"));
    } catch (ConfigurationException ex) {
      Assert.fail("Not expected ConfigurationException");
    }
    try {
      serverNameMatch.validate(new PrivilegeValidatorContext("server=server1->consumer_group=g1->action=read"));
    } catch (ConfigurationException ex) {
      Assert.fail("Not expected ConfigurationException");
    }
  }

}
