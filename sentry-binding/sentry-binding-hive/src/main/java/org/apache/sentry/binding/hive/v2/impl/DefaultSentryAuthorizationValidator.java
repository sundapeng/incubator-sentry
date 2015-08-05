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

import static org.apache.hadoop.hive.metastore.MetaStoreUtils.DEFAULT_DATABASE_NAME;

import java.security.CodeSource;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.hive.ql.metadata.AuthorizationException;
import org.apache.hadoop.hive.ql.plan.HiveOperation;
import org.apache.hadoop.hive.ql.security.HiveAuthenticationProvider;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HiveAuthzContext;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HiveOperationType;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HivePrivilegeObject;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HivePrivilegeObject.HivePrivilegeObjectType;
import org.apache.hadoop.hive.ql.session.SessionState;
import org.apache.sentry.binding.hive.SentryOnFailureHookContext;
import org.apache.sentry.binding.hive.SentryOnFailureHookContextImpl;
import org.apache.sentry.binding.hive.authz.HiveAuthzBinding;
import org.apache.sentry.binding.hive.authz.HiveAuthzBinding.HiveHook;
import org.apache.sentry.binding.hive.authz.HiveAuthzPrivileges.HiveOperationScope;
import org.apache.sentry.binding.hive.authz.HiveAuthzPrivileges;
import org.apache.sentry.binding.hive.authz.HiveAuthzPrivilegesMap;
import org.apache.sentry.binding.hive.conf.HiveAuthzConf;
import org.apache.sentry.binding.hive.v2.SentryAuthorizationValidator;
import org.apache.sentry.binding.hive.v2.util.SentryAccessControlException;
import org.apache.sentry.binding.hive.v2.util.SentryAuthorizerUtil;
import org.apache.sentry.core.common.Subject;
import org.apache.sentry.core.model.db.AccessURI;
import org.apache.sentry.core.model.db.Column;
import org.apache.sentry.core.model.db.DBModelAction;
import org.apache.sentry.core.model.db.DBModelAuthorizable;
import org.apache.sentry.core.model.db.Database;
import org.apache.sentry.core.model.db.Table;
import org.apache.sentry.core.model.db.DBModelAuthorizable.AuthorizableType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Sets;

public class DefaultSentryAuthorizationValidator extends SentryAuthorizationValidator {

  public static final Logger LOG = LoggerFactory.getLogger(DefaultSentryAuthorizationValidator.class);
  private HiveHook hiveHook;

  // all operations need to extend at DB scope
  private static final Set<HiveOperation> EX_DB_ALL = Sets.newHashSet(HiveOperation.DROPDATABASE,
      HiveOperation.CREATETABLE, HiveOperation.IMPORT, HiveOperation.DESCDATABASE,
      HiveOperation.ALTERTABLE_RENAME, HiveOperation.LOCKDB, HiveOperation.UNLOCKDB);
  // input operations need to extend at DB scope
  private static final Set<HiveOperation> EX_DB_INPUT = Sets.newHashSet(HiveOperation.DROPDATABASE,
      HiveOperation.DESCDATABASE, HiveOperation.ALTERTABLE_RENAME,
      HiveOperation.LOCKDB, HiveOperation.UNLOCKDB);

  // all operations need to extend at Table scope
  private static final Set<HiveOperation> EX_TB_ALL = Sets.newHashSet(
      HiveOperation.DROPTABLE,
      HiveOperation.DROPVIEW,
      HiveOperation.DESCTABLE,
      HiveOperation.SHOW_TBLPROPERTIES,
      HiveOperation.SHOWINDEXES,
      HiveOperation.ALTERTABLE_PROPERTIES,
      HiveOperation.ALTERTABLE_SERDEPROPERTIES,
      HiveOperation.ALTERTABLE_CLUSTER_SORT,
      HiveOperation.ALTERTABLE_FILEFORMAT,
      HiveOperation.ALTERTABLE_TOUCH,
      HiveOperation.ALTERTABLE_PROTECTMODE,
      HiveOperation.ALTERTABLE_RENAMECOL,
      HiveOperation.ALTERTABLE_ADDCOLS,
      HiveOperation.ALTERTABLE_REPLACECOLS,
      HiveOperation.ALTERTABLE_RENAMEPART,
      HiveOperation.ALTERTABLE_ARCHIVE,
      HiveOperation.ALTERTABLE_UNARCHIVE,
      HiveOperation.ALTERTABLE_SERIALIZER,
      HiveOperation.ALTERTABLE_MERGEFILES,
      HiveOperation.ALTERTABLE_SKEWED,
      HiveOperation.ALTERTABLE_DROPPARTS,
      HiveOperation.ALTERTABLE_ADDPARTS,
      HiveOperation.ALTERTABLE_RENAME,
      HiveOperation.ALTERTABLE_LOCATION,
      HiveOperation.ALTERVIEW_PROPERTIES,
      HiveOperation.ALTERPARTITION_FILEFORMAT,
      HiveOperation.ALTERPARTITION_PROTECTMODE,
      HiveOperation.ALTERPARTITION_SERDEPROPERTIES,
      HiveOperation.ALTERPARTITION_SERIALIZER,
      HiveOperation.ALTERPARTITION_MERGEFILES,
      HiveOperation.ALTERPARTITION_LOCATION,
      HiveOperation.ALTERTBLPART_SKEWED_LOCATION,
      HiveOperation.MSCK,
      HiveOperation.ALTERINDEX_REBUILD,
      HiveOperation.LOCKTABLE,
      HiveOperation.UNLOCKTABLE,
      HiveOperation.SHOWCOLUMNS);
  // input operations need to extend at Table scope
  private static final Set<HiveOperation> EX_TB_INPUT = Sets.newHashSet(HiveOperation.DROPTABLE,
      HiveOperation.DROPVIEW, HiveOperation.DESCTABLE, HiveOperation.SHOW_TBLPROPERTIES,
      HiveOperation.SHOWINDEXES, HiveOperation.ALTERINDEX_REBUILD,
      HiveOperation.LOCKTABLE, HiveOperation.UNLOCKTABLE, HiveOperation.SHOWCOLUMNS);

  public DefaultSentryAuthorizationValidator(
      HiveConf conf,
      HiveAuthzConf authzConf,
      HiveAuthenticationProvider authenticator) throws Exception {
    this(HiveHook.HiveServer2, conf, authzConf, authenticator);
  }

  public DefaultSentryAuthorizationValidator(HiveHook hiveHook, HiveConf conf,
      HiveAuthzConf authzConf,  HiveAuthenticationProvider authenticator) throws Exception {
    super(conf, authzConf, authenticator);
    this.hiveHook = hiveHook;
  }

  @Override
  public void checkPrivileges(HiveOperationType hiveOpType,
      List<HivePrivilegeObject> inputHObjs,
      List<HivePrivilegeObject> outputHObjs,
      HiveAuthzContext context) throws SentryAccessControlException {
    if (LOG.isDebugEnabled()) {
      String msg = "Checking privileges for operation " + hiveOpType + " by user "
          + authenticator.getUserName() + " on " + " input objects " + inputHObjs
          + " and output objects " + outputHObjs + ". Context Info: " + context;
      LOG.debug(msg);
    }

    HiveOperation hiveOp = SentryAuthorizerUtil.convert2HiveOperation(hiveOpType.name());
    HiveAuthzPrivileges stmtAuthPrivileges = HiveAuthzPrivilegesMap.getHiveAuthzPrivileges(hiveOp);

    HiveAuthzBinding hiveAuthzBinding = null;
    try {
      hiveAuthzBinding = getAuthzBinding();
      if (stmtAuthPrivileges == null) {
        // We don't handle authorizing this statement
        return;
      }

      List<List<DBModelAuthorizable>> inputHierarchyList =
          SentryAuthorizerUtil.convert2SentryPrivilegeList(hiveAuthzBinding.getAuthServer(), inputHObjs);
      List<List<DBModelAuthorizable>> outputHierarchyList =
          SentryAuthorizerUtil.convert2SentryPrivilegeList(hiveAuthzBinding.getAuthServer(), outputHObjs);

      // Workaround for metadata queries
      addExtendHierarchy(hiveOp, stmtAuthPrivileges, inputHierarchyList,
          outputHierarchyList, context.getCommandString(), hiveAuthzBinding);

      hiveAuthzBinding.authorize(hiveOp, stmtAuthPrivileges, new Subject(authenticator.getUserName()),
          inputHierarchyList, outputHierarchyList);
    } catch (AuthorizationException e) {
      Database db = null;
      Table tab = null;
      AccessURI udfURI = null;
      AccessURI partitionURI = null;
      if (outputHObjs!=null) {
        for (HivePrivilegeObject obj : outputHObjs) {
          switch (obj.getType()) {
            case DATABASE:
              db = new Database(obj.getObjectName());
              break;
            case TABLE_OR_VIEW:
              db = new Database(obj.getDbname());
              tab = new Table(obj.getObjectName());
              break;
            case PARTITION:
              db = new Database(obj.getDbname());
              tab = new Table(obj.getObjectName());
            case LOCAL_URI:
            case DFS_URI:
          }
        }
      }
      SentryOnFailureHookContext hookCtx = new SentryOnFailureHookContextImpl(
          context.getCommandString(), null, null,
          hiveOp, db, tab, udfURI, partitionURI, authenticator.getUserName(),
          context.getIpAddress(), e, authzConf);
      SentryAuthorizerUtil.executeOnFailureHooks(hookCtx, authzConf);
      String permsRequired = "";
      for (String perm : hiveAuthzBinding.getLastQueryPrivilegeErrors()) {
        permsRequired += perm + ";";
      }
      SessionState.get().getConf().set(HiveAuthzConf.HIVE_SENTRY_AUTH_ERRORS, permsRequired);
      String msg = HiveAuthzConf.HIVE_SENTRY_PRIVILEGE_ERROR_MESSAGE + "\n Required privileges for this query: "
          + permsRequired;
      throw new SentryAccessControlException(msg, e);
    } catch (Exception e) {
      throw new SentryAccessControlException(e);
    } finally {
      if (hiveAuthzBinding != null) {
        hiveAuthzBinding.close();
      }
    }

    if ("true".equalsIgnoreCase(SessionState.get().getConf().get(HiveAuthzConf.HIVE_SENTRY_MOCK_COMPILATION))) {
      throw new SentryAccessControlException(HiveAuthzConf.HIVE_SENTRY_MOCK_ERROR +
          " Mock query compilation aborted. Set " + HiveAuthzConf.HIVE_SENTRY_MOCK_COMPILATION +
          " to 'false' for normal query processing");
    }
  }

  @VisibleForTesting
  public HiveAuthzBinding getAuthzBinding() throws Exception {
    return new HiveAuthzBinding(hiveHook, conf, authzConf);
  }

  private void addExtendHierarchy(HiveOperation hiveOp, HiveAuthzPrivileges stmtAuthPrivileges,
      List<List<DBModelAuthorizable>> inputHierarchyList,
      List<List<DBModelAuthorizable>> outputHierarchyList,
      String command, HiveAuthzBinding hiveAuthzBinding) throws SentryAccessControlException {
    String currDatabase = null;
    switch (stmtAuthPrivileges.getOperationScope()) {
      case SERVER:
        // validate server level privileges if applicable. Eg create UDF,register jar etc ..
        List<DBModelAuthorizable> serverHierarchy = new ArrayList<DBModelAuthorizable>();
        serverHierarchy.add(hiveAuthzBinding.getAuthServer());
        inputHierarchyList.add(serverHierarchy);
        break;
      case DATABASE:
        // workaround for metadata queries.
        if (EX_DB_ALL.contains(hiveOp)) {
          SimpleSemanticAnalyzer analyzer = new SimpleSemanticAnalyzer(hiveOp, command);
          currDatabase = analyzer.getCurrentDb();

          List<DBModelAuthorizable> externalAuthorizableHierarchy = new ArrayList<DBModelAuthorizable>();
          externalAuthorizableHierarchy.add(hiveAuthzBinding.getAuthServer());
          externalAuthorizableHierarchy.add(new Database(currDatabase));

          if (EX_DB_INPUT.contains(hiveOp)) {
            inputHierarchyList.add(externalAuthorizableHierarchy);
          } else {
            outputHierarchyList.add(externalAuthorizableHierarchy);
          }
        }
        break;
      case TABLE:
        // workaround for drop table/view.
        if (EX_TB_ALL.contains(hiveOp)) {
          SimpleSemanticAnalyzer analyzer = new SimpleSemanticAnalyzer(hiveOp, command);
          currDatabase = analyzer.getCurrentDb();
          String currTable = analyzer.getCurrentTb();

          List<DBModelAuthorizable> externalAuthorizableHierarchy = new ArrayList<DBModelAuthorizable>();
          externalAuthorizableHierarchy.add(hiveAuthzBinding.getAuthServer());
          externalAuthorizableHierarchy.add(new Database(currDatabase));
          externalAuthorizableHierarchy.add(new Table(currTable));

          if (EX_TB_INPUT.contains(hiveOp)) {
            inputHierarchyList.add(externalAuthorizableHierarchy);
          } else {
            outputHierarchyList.add(externalAuthorizableHierarchy);
          }
        }
        break;
      case FUNCTION:
        if (hiveOp.equals(HiveOperation.CREATEFUNCTION)) {
          SimpleSemanticAnalyzer analyzer = new SimpleSemanticAnalyzer(hiveOp, command);
          currDatabase = analyzer.getCurrentDb();
          String udfClassName = analyzer.getCurrentTb();
          try {
            CodeSource udfSrc = Class.forName(udfClassName).getProtectionDomain().getCodeSource();
            if (udfSrc == null) {
              throw new SentryAccessControlException("Could not resolve the jar for UDF class " + udfClassName);
            }
            String udfJar = udfSrc.getLocation().getPath();
            if (udfJar == null || udfJar.isEmpty()) {
              throw new SentryAccessControlException("Could not find the jar for UDF class " + udfClassName +
                  "to validate privileges");
            }
            AccessURI udfURI = SentryAuthorizerUtil.parseURI(udfSrc.getLocation().toString(), true);
            List<DBModelAuthorizable> udfUriHierarchy = new ArrayList<DBModelAuthorizable>();
            udfUriHierarchy.add(hiveAuthzBinding.getAuthServer());
            udfUriHierarchy.add(udfURI);
            inputHierarchyList.add(udfUriHierarchy);
          } catch (Exception e) {
            throw new SentryAccessControlException("Error retrieving udf class", e);
          }
        }
        break;
      case CONNECT:
        /* The 'CONNECT' is an implicit privilege scope currently used for
         *  - USE <db>
         *  It's allowed when the user has any privilege on the current database. For application
         *  backward compatibility, we allow (optional) implicit connect permission on 'default' db.
         */
        List<DBModelAuthorizable> connectHierarchy = new ArrayList<DBModelAuthorizable>();
        connectHierarchy.add(hiveAuthzBinding.getAuthServer());
        if (hiveOp.equals(HiveOperation.SWITCHDATABASE)) {
          currDatabase = command.split(" ")[1];
        }
        // by default allow connect access to default db
        Table currTbl = Table.ALL;
        Database currDB = new Database(currDatabase);
        Column currCol = Column.ALL;
        if ((DEFAULT_DATABASE_NAME.equalsIgnoreCase(currDatabase) &&
            "false".equalsIgnoreCase(authzConf.
                get(HiveAuthzConf.AuthzConfVars.AUTHZ_RESTRICT_DEFAULT_DB.getVar(), "false")))) {
          currDB = Database.ALL;
          currTbl = Table.SOME;
        }

        connectHierarchy.add(currDB);
        connectHierarchy.add(currTbl);
        connectHierarchy.add(currCol);

        inputHierarchyList.add(connectHierarchy);
        break;
    }
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
            listObjs = filterShowDatabases(listObjs, authenticator.getUserName(), hiveAuthzBinding);
            break;
          case TABLE_OR_VIEW:
            hiveAuthzBinding = getAuthzBinding();
            listObjs = filterShowTables(listObjs, authenticator.getUserName(), hiveAuthzBinding);
            break;
        }
      } catch (Exception e) {
        // ignore
      } finally {
        if (hiveAuthzBinding != null) {
          hiveAuthzBinding.close();
        }
      }
    }
    return listObjs;
  }

  private List<HivePrivilegeObject> filterShowTables(List<HivePrivilegeObject> listObjs,
      String userName, HiveAuthzBinding hiveAuthzBinding) {
    List<HivePrivilegeObject> filteredResult = new ArrayList<HivePrivilegeObject>();
    Subject subject = new Subject(userName);
    HiveAuthzPrivileges tableMetaDataPrivilege = new HiveAuthzPrivileges.AuthzPrivilegeBuilder().
        addInputObjectPriviledge(AuthorizableType.Column, EnumSet.of(DBModelAction.SELECT, DBModelAction.INSERT)).
        setOperationScope(HiveOperationScope.TABLE).
        setOperationType(
            org.apache.sentry.binding.hive.authz.HiveAuthzPrivileges.HiveOperationType.INFO).
        build();

    for (HivePrivilegeObject obj : listObjs) {
      // if user has privileges on table, add to filtered list, else discard
      Table table = new Table(obj.getObjectName());
      Database database;
      database = new Database(obj.getDbname());

      List<List<DBModelAuthorizable>> inputHierarchy = new ArrayList<List<DBModelAuthorizable>>();
      List<List<DBModelAuthorizable>> outputHierarchy = new ArrayList<List<DBModelAuthorizable>>();
      List<DBModelAuthorizable> externalAuthorizableHierarchy = new ArrayList<DBModelAuthorizable>();
      externalAuthorizableHierarchy.add(hiveAuthzBinding.getAuthServer());
      externalAuthorizableHierarchy.add(database);
      externalAuthorizableHierarchy.add(table);
      externalAuthorizableHierarchy.add(Column.ALL);
      inputHierarchy.add(externalAuthorizableHierarchy);

      try {
        hiveAuthzBinding.authorize(HiveOperation.SHOWTABLES, tableMetaDataPrivilege, subject,
            inputHierarchy, outputHierarchy);
        filteredResult.add(obj);
      } catch (AuthorizationException e) {
        // squash the exception, user doesn't have privileges, so the table is
        // not added to
        // filtered list.
        ;
      }
    }
    return filteredResult;
  }

  private List<HivePrivilegeObject> filterShowDatabases(List<HivePrivilegeObject> listObjs,
      String userName, HiveAuthzBinding hiveAuthzBinding) {
    List<HivePrivilegeObject> filteredResult = new ArrayList<HivePrivilegeObject>();
    Subject subject = new Subject(userName);
    HiveAuthzPrivileges anyPrivilege =
        new HiveAuthzPrivileges.AuthzPrivilegeBuilder()
            .addInputObjectPriviledge(
                AuthorizableType.Column,
                EnumSet.of(DBModelAction.SELECT, DBModelAction.INSERT, DBModelAction.ALTER,
                    DBModelAction.CREATE, DBModelAction.DROP, DBModelAction.INDEX,
                    DBModelAction.LOCK))
            .setOperationScope(HiveOperationScope.CONNECT)
            .setOperationType(
                org.apache.sentry.binding.hive.authz.HiveAuthzPrivileges.HiveOperationType.QUERY)
            .build();

    for (HivePrivilegeObject obj : listObjs) {
      // if user has privileges on database, add to filtered list, else discard
      Database database = null;

      // if default is not restricted, continue
      if (DEFAULT_DATABASE_NAME.equalsIgnoreCase(obj.getObjectName())
          && "false".equalsIgnoreCase(hiveAuthzBinding.getAuthzConf().get(
              HiveAuthzConf.AuthzConfVars.AUTHZ_RESTRICT_DEFAULT_DB.getVar(), "false"))) {
        filteredResult.add(obj);
        continue;
      }

      database = new Database(obj.getObjectName());

      List<List<DBModelAuthorizable>> inputHierarchy = new ArrayList<List<DBModelAuthorizable>>();
      List<List<DBModelAuthorizable>> outputHierarchy = new ArrayList<List<DBModelAuthorizable>>();
      List<DBModelAuthorizable> externalAuthorizableHierarchy =
          new ArrayList<DBModelAuthorizable>();
      externalAuthorizableHierarchy.add(hiveAuthzBinding.getAuthServer());
      externalAuthorizableHierarchy.add(database);
      externalAuthorizableHierarchy.add(Table.ALL);
      externalAuthorizableHierarchy.add(Column.ALL);
      inputHierarchy.add(externalAuthorizableHierarchy);

      try {
        hiveAuthzBinding.authorize(HiveOperation.SHOWDATABASES, anyPrivilege, subject,
            inputHierarchy, outputHierarchy);
        filteredResult.add(obj);
      } catch (AuthorizationException e) {
        // squash the exception, user doesn't have privileges, so the table is
        // not added to
        // filtered list.
        ;
      }
    }
    return filteredResult;
  }

}
