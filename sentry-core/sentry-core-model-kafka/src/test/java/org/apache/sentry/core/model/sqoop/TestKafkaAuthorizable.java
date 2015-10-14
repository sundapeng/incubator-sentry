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

package org.apache.sentry.core.model.sqoop;

import junit.framework.Assert;

import org.apache.sentry.core.model.kafka.Cluster;
import org.apache.sentry.core.model.kafka.ConsumerGroup;
import org.apache.sentry.core.model.kafka.KafkaAuthorizable.AuthorizableType;
import org.apache.sentry.core.model.kafka.Server;
import org.apache.sentry.core.model.kafka.Topic;
import org.junit.Test;

public class TestKafkaAuthorizable {

  @Test
  public void testSimpleName() throws Exception {
    String name = "simple";
    Server server = new Server(name);
    Assert.assertEquals(server.getName(), name);

    Cluster cluster = new Cluster(name);
    Assert.assertEquals(cluster.getName(), name);

    Topic topic = new Topic(name);
    Assert.assertEquals(topic.getName(), name);

    ConsumerGroup consumerGroup = new ConsumerGroup(name);
    Assert.assertEquals(consumerGroup.getName(), name);
  }

  @Test
  public void testAuthType() throws Exception {
    Server server = new Server("server1");
    Assert.assertEquals(server.getAuthzType(), AuthorizableType.SERVER);

    Cluster cluster = new Cluster("cluster1");
    Assert.assertEquals(cluster.getAuthzType(), AuthorizableType.CLUSTER);

    Topic topic = new Topic("topic1");
    Assert.assertEquals(topic.getAuthzType(), AuthorizableType.TOPIC);

    ConsumerGroup consumerGroup = new ConsumerGroup("consumerGroup1");
    Assert.assertEquals(consumerGroup.getAuthzType(), AuthorizableType.CONSUMERGROUP);
  }
}
