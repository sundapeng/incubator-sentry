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
package org.apache.sentry.binding.hive;

import java.util.List;

import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.hive.ql.plan.HiveOperation;
import org.apache.hadoop.hive.ql.security.HiveAuthenticationProvider;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HiveAccessControlException;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HiveAuthorizationValidator;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HiveAuthzContext;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HiveAuthzPluginException;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HiveOperationType;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HivePrivilegeObject;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HivePrivilegeObject.HivePrivilegeObjectType;
import org.apache.sentry.binding.hive.authz.HiveAuthzBinding;
import org.apache.sentry.binding.hive.conf.HiveAuthzConf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class DefaultSentryValidator implements HiveAuthorizationValidator {
  private static final Logger LOG = LoggerFactory
      .getLogger(DefaultSentryValidator.class);
  
  private HiveConf hiveConf;
  private HiveAuthzConf authzConf;
  private HiveAuthenticationProvider authenticator;

  public DefaultSentryValidator(HiveConf conf, HiveAuthzConf loadAuthzConf, HiveAuthenticationProvider authenticator) {
    this.hiveConf = conf;
    this.authzConf = loadAuthzConf;
    this.authenticator = authenticator;
  }

  @Override
  public void checkPrivileges(HiveOperationType hiveOpType, List<HivePrivilegeObject> inputHObjs,
      List<HivePrivilegeObject> outputHObjs, HiveAuthzContext context)
      throws HiveAuthzPluginException, HiveAccessControlException {
  }

  @Override
  public List<HivePrivilegeObject> filterListCmdObjects(List<HivePrivilegeObject> listObjs,
      HiveAuthzContext context) {
    if (listObjs != null && listObjs.size() >= 1) {
      HivePrivilegeObjectType pType = listObjs.get(0).getType();
      HiveAuthzBinding hiveAuthzBinding = null;
      try {
        switch (pType) {
          case DATABASE:
            hiveAuthzBinding = getAuthzBinding();
            listObjs = HiveAuthzBindingHook.filterShowDatabasesPrivilegeObject(hiveAuthzBinding, listObjs, HiveOperation.SHOWDATABASES, authenticator.getUserName());
            break;
          case TABLE_OR_VIEW:
            hiveAuthzBinding = getAuthzBinding();
            listObjs = HiveAuthzBindingHook.filterShowTablesPrivilegeObject(hiveAuthzBinding, listObjs, HiveOperation.SHOWTABLES, authenticator.getUserName());
            break;
        }
      } catch (Exception e) {
        LOG.debug(e.getMessage(), e);
      } finally {
        if (hiveAuthzBinding != null) {
          hiveAuthzBinding.close();
        }
      }
    }
    return listObjs;
  }

  

  private HiveAuthzBinding getAuthzBinding() throws Exception {
    return new HiveAuthzBinding(hiveConf, authzConf);
  }
}