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
package org.apache.sentry.binding.hive.v2;

import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.CodeSource;
import java.util.List;

import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.hive.ql.exec.DDLTask;
import org.apache.hadoop.hive.ql.exec.SentryFilterDDLTask;
import org.apache.hadoop.hive.ql.exec.Task;
import org.apache.hadoop.hive.ql.metadata.AuthorizationException;
import org.apache.hadoop.hive.ql.parse.ASTNode;
import org.apache.hadoop.hive.ql.parse.BaseSemanticAnalyzer;
import org.apache.hadoop.hive.ql.parse.HiveParser;
import org.apache.hadoop.hive.ql.parse.HiveSemanticAnalyzerHookContext;
import org.apache.hadoop.hive.ql.parse.SemanticException;
import org.apache.hadoop.hive.ql.plan.DDLWork;
import org.apache.hadoop.hive.ql.plan.HiveOperation;
import org.apache.hadoop.hive.ql.session.SessionState;
import org.apache.sentry.binding.hive.HiveAuthzBindingHook;
import org.apache.sentry.binding.hive.authz.HiveAuthzBinding;
import org.apache.sentry.binding.hive.authz.HiveAuthzPrivileges;
import org.apache.sentry.binding.hive.authz.HiveAuthzPrivilegesMap;
import org.apache.sentry.binding.hive.conf.HiveAuthzConf;
import org.apache.sentry.core.common.Subject;
import org.apache.sentry.core.model.db.Database;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HiveAuthzBindingHookV2 extends HiveAuthzBindingHook {
  private static final Logger LOG = LoggerFactory
      .getLogger(HiveAuthzBindingHookV2.class);
  private final HiveAuthzBinding hiveAuthzBinding;
  private final HiveAuthzConf authzConf;

  public HiveAuthzBindingHookV2() throws Exception {
    SessionState session = SessionState.get();
    if(session == null) {
      throw new IllegalStateException("Session has not been started");
    }

    HiveConf hiveConf = session.getConf();
    if(hiveConf == null) {
      throw new IllegalStateException("Session HiveConf is null");
    }
    authzConf = loadAuthzConf(hiveConf);
    hiveAuthzBinding = new HiveAuthzBinding(hiveConf, authzConf);
  }

  public static HiveAuthzConf loadAuthzConf(HiveConf hiveConf) {
    boolean depreicatedConfigFile = false;
    HiveAuthzConf newAuthzConf = null;
    String hiveAuthzConf = hiveConf.get(HiveAuthzConf.HIVE_SENTRY_CONF_URL);
    if(hiveAuthzConf == null || (hiveAuthzConf = hiveAuthzConf.trim()).isEmpty()) {
      hiveAuthzConf = hiveConf.get(HiveAuthzConf.HIVE_ACCESS_CONF_URL);
      depreicatedConfigFile = true;
    }

    if(hiveAuthzConf == null || (hiveAuthzConf = hiveAuthzConf.trim()).isEmpty()) {
      throw new IllegalArgumentException("Configuration key " + HiveAuthzConf.HIVE_SENTRY_CONF_URL
          + " value '" + hiveAuthzConf + "' is invalid.");
    }
    try {
      newAuthzConf = new HiveAuthzConf(new URL(hiveAuthzConf));
    } catch (MalformedURLException e) {
      if (depreicatedConfigFile) {
        throw new IllegalArgumentException("Configuration key " + HiveAuthzConf.HIVE_ACCESS_CONF_URL
            + " specifies a malformed URL '" + hiveAuthzConf + "'", e);
      } else {
        throw new IllegalArgumentException("Configuration key " + HiveAuthzConf.HIVE_SENTRY_CONF_URL
            + " specifies a malformed URL '" + hiveAuthzConf + "'", e);
      }
    }
    return newAuthzConf;
  }

  @Override
  public ASTNode preAnalyze(HiveSemanticAnalyzerHookContext context, ASTNode ast)
      throws SemanticException {

    switch (ast.getToken().getType()) {
    // Hive parser doesn't capture the database name in output entity, so we store it here for now
      case HiveParser.TOK_CREATEFUNCTION:
        String udfClassName = BaseSemanticAnalyzer.unescapeSQLString(ast.getChild(1).getText());
        try {
          CodeSource udfSrc = Class.forName(udfClassName).getProtectionDomain().getCodeSource();
          if (udfSrc == null) {
            throw new SemanticException("Could not resolve the jar for UDF class " + udfClassName);
          }
          String udfJar = udfSrc.getLocation().getPath();
          if (udfJar == null || udfJar.isEmpty()) {
            throw new SemanticException("Could not find the jar for UDF class " + udfClassName +
                "to validate privileges");
          }
          udfURI = parseURI(udfSrc.getLocation().toString(), true);
        } catch (ClassNotFoundException e) {
          throw new SemanticException("Error retrieving udf class", e);
        }
        // create/drop function is allowed with any database
        currDB = Database.ALL;
        break;
      case HiveParser.TOK_DROPFUNCTION:
        // create/drop function is allowed with any database
        currDB = Database.ALL;
        break;
    }
    return ast;
  }

  /**
   * Post analyze hook that invokes hive auth bindings
   */
  @Override
  public void postAnalyze(HiveSemanticAnalyzerHookContext context,
      List<Task<? extends Serializable>> rootTasks) throws SemanticException {
    HiveOperation stmtOperation = getCurrentHiveStmtOp();
    Subject subject = new Subject(context.getUserName());
    for (int i = 0; i < rootTasks.size(); i++) {
      Task<? extends Serializable> task = rootTasks.get(i);
      if (task instanceof DDLTask) {
        SentryFilterDDLTask filterTask =
            new SentryFilterDDLTask(hiveAuthzBinding, subject, stmtOperation);
        filterTask.setWork((DDLWork)task.getWork());
        rootTasks.set(i, filterTask);
      }
    }
    
    HiveAuthzPrivileges stmtAuthObject = HiveAuthzPrivilegesMap.getHiveAuthzPrivileges(stmtOperation);
    if (stmtOperation.equals(HiveOperation.CREATEFUNCTION)
        || stmtOperation.equals(HiveOperation.DROPFUNCTION)) {
      try {
        if (stmtAuthObject == null) {
          // We don't handle authorizing this statement
          return;
        }

        authorizeWithHiveBindings(context, stmtAuthObject, stmtOperation);
      } catch (AuthorizationException e) {
        executeOnFailureHooks(context, stmtOperation, e);
        String permsRequired = "";
        for (String perm : hiveAuthzBinding.getLastQueryPrivilegeErrors()) {
          permsRequired += perm + ";";
        }
        SessionState.get().getConf().set(HiveAuthzConf.HIVE_SENTRY_AUTH_ERRORS, permsRequired);
        String msgForLog =
            HiveAuthzConf.HIVE_SENTRY_PRIVILEGE_ERROR_MESSAGE
                + "\n Required privileges for this query: " + permsRequired;
        String msgForConsole =
            HiveAuthzConf.HIVE_SENTRY_PRIVILEGE_ERROR_MESSAGE + "\n " + e.getMessage();
        // AuthorizationException is not a real exception, use the info level to record this.
        LOG.info(msgForLog);
        throw new SemanticException(msgForConsole, e);
      } finally {
        hiveAuthzBinding.close();
      }
    }
  }

  private HiveOperation getCurrentHiveStmtOp() {
    SessionState sessState = SessionState.get();
    if (sessState == null) {
      LOG.warn("SessionState is null");
      return null;
    }
    return sessState.getHiveOperation();
  }

}
