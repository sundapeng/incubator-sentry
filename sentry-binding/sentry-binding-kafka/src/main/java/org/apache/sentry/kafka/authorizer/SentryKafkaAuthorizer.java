/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.sentry.kafka.authorizer;

import kafka.network.RequestChannel;
import kafka.security.auth.Acl;
import kafka.security.auth.Authorizer;
import kafka.security.auth.ConsumerGroup;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.sentry.kafka.binding.KafkaAuthBinding;
import org.apache.sentry.kafka.binding.KafkaAuthBindingSingleton;
import org.apache.sentry.kafka.conf.KafkaAuthConf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import scala.collection.immutable.HashMap;
import scala.collection.immutable.HashSet;
import scala.collection.immutable.Map;
import scala.collection.immutable.Set;

public class SentryKafkaAuthorizer implements Authorizer {
  
  private static Logger LOG =
      LoggerFactory.getLogger(SentryKafkaAuthorizer.class);

  KafkaAuthBinding binding;
  
  String sentry_site = null;
  
  public SentryKafkaAuthorizer() {
    
  }
  
  @Override
  public boolean authorize(RequestChannel.Session session, Operation operation,
                           Resource resource) {
    LOG.info("Authorizing" + session + operation + resource);
    // If resource type if consumer group, then allow it by default
    if (resource.resourceType().name().equals(ConsumerGroup.name())) {
      return true;
    }
    return binding.authorize(session, operation, resource);
  }

  @Override
  public void addAcls(Set<Acl> acls, Resource resource) {
    LOG.error("addAcls() is not supported: acl->" + acls +" resource->"+ resource);
  }

  @Override
  public boolean removeAcls(Set<Acl> acls, Resource resource) {
    LOG.error("removeAcls() is not supported: acl->" + acls +" resource->"+ resource);
    return false;
  }

  @Override
  public boolean removeAcls(Resource resource) {
    LOG.error("removeAcls() is not supported: resource->"+  resource);
    return false;
  }

  @Override
  public Set<Acl> getAcls(Resource resource) {
    LOG.error("getAcls() is not supported: resource->" + resource);
    return new HashSet<Acl>();
  }

  @Override
  public Map<Resource, Set<Acl>> getAcls(KafkaPrincipal principal) {
    LOG.error("getAcls() is not supported: principal->" + principal);
    return new HashMap<Resource, Set<Acl>>();
  }

  @Override
  public void configure(java.util.Map<String, ?> configs) {
    sentry_site = configs.get(KafkaAuthConf.SENTRY_KAFKA_SITE_URL).toString();
    LOG.info("Configuring Sentry KafkaAuthorizer: " + sentry_site);
    this.binding = KafkaAuthBindingSingleton.getInstance(sentry_site).getAuthBinding();
  }
}
