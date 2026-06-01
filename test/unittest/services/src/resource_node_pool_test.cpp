/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "resource_node_pool_test.h"

#include "iam_ptr.h"
#include "resource_node_pool.h"

#include "mock_resource_node.h"
#include "mock_resource_node_pool_listener.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ResourceNodePoolTest::SetUpTestCase()
{
}

void ResourceNodePoolTest::TearDownTestCase()
{
}

void ResourceNodePoolTest::SetUp()
{
}

void ResourceNodePoolTest::TearDown()
{
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(ResourceNodePoolTest, ResourceNodePoolGetInstance, TestSize.Level0)
{
    auto &pool = ResourceNodePool::Instance();
    EXPECT_NE(&pool, nullptr);
}

HWTEST_F(ResourceNodePoolTest, ResourceNodePoolGetUniqueInstance, TestSize.Level0)
{
    auto &pool1 = ResourceNodePool::Instance();
    auto &pool2 = ResourceNodePool::Instance();
    EXPECT_EQ(&pool1, &pool2);
}

HWTEST_F(ResourceNodePoolTest, ResourceNodePoolInsertNull, TestSize.Level0)
{
    EXPECT_EQ(ResourceNodePool::Instance().Insert(nullptr), false);
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(ResourceNodePoolTest, ResourceNodePoolInsertDuplicateId, TestSize.Level0)
{
    const uint64_t EXECUTOR_INDEX = 100;
    auto resource1 = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX, true);
    auto resource2 = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX);
    ASSERT_NE(resource1, resource2);
    auto &pool = ResourceNodePool::Instance();

    EXPECT_EQ(pool.Insert(resource1), true);
    EXPECT_EQ(pool.Select(EXECUTOR_INDEX).lock(), resource1);
    EXPECT_EQ(pool.Insert(resource2), true);
    EXPECT_EQ(pool.Select(EXECUTOR_INDEX).lock(), resource2);

    EXPECT_EQ(pool.Delete(EXECUTOR_INDEX), true);
    EXPECT_EQ(pool.Delete(EXECUTOR_INDEX), true);
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(ResourceNodePoolTest, ResourceNodePoolDelete, TestSize.Level0)
{
    const uint64_t EXECUTOR_INDEX = 200;
    auto &pool = ResourceNodePool::Instance();
    EXPECT_EQ(pool.Delete(EXECUTOR_INDEX), false);
    auto resource = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX);
    EXPECT_EQ(pool.Insert(resource), true);
    EXPECT_EQ(pool.Delete(EXECUTOR_INDEX), true);
    EXPECT_EQ(pool.Select(EXECUTOR_INDEX).lock(), nullptr);
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(ResourceNodePoolTest, ResourceNodePoolInsertAndDelete, TestSize.Level0)
{
    auto &pool = ResourceNodePool::Instance();
    const uint64_t EXECUTOR_INDEX1 = 300;
    const uint64_t EXECUTOR_INDEX2 = 400;
    const uint64_t EXECUTOR_INDEX3 = 500;
    auto resource1 = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX1);
    auto resource2 = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX2);
    auto resource3 = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX3);
    EXPECT_EQ(pool.Insert(resource1), true);
    EXPECT_EQ(pool.Insert(resource2), true);
    EXPECT_EQ(pool.Insert(resource3), true);
    EXPECT_EQ(pool.Select(EXECUTOR_INDEX3).lock(), resource3);
    EXPECT_EQ(pool.Select(EXECUTOR_INDEX2).lock(), resource2);
    EXPECT_EQ(pool.Select(EXECUTOR_INDEX1).lock(), resource1);

    EXPECT_EQ(pool.GetPoolSize(), 3U);
    pool.DeleteAll();

    EXPECT_NE(pool.Select(EXECUTOR_INDEX3).lock(), resource3);
    EXPECT_NE(pool.Select(EXECUTOR_INDEX2).lock(), resource2);
    EXPECT_NE(pool.Select(EXECUTOR_INDEX1).lock(), resource1);
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(ResourceNodePoolTest, ResourceNodePoolListenerInsert, TestSize.Level0)
{
    auto &pool = ResourceNodePool::Instance();
    const uint64_t EXECUTOR_INDEX1 = 300;
    const uint64_t EXECUTOR_INDEX2 = 400;
    const uint64_t EXECUTOR_INDEX3 = 500;
    auto resource1 = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX1);
    auto resource2 = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX2);
    auto resource3 = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX3);

    MockFunction<void(MockResourceNodePoolListener::Action action, const std::shared_ptr<ResourceNode> &resource)>
        callback1;
    MockFunction<void(MockResourceNodePoolListener::Action action, const std::shared_ptr<ResourceNode> &resource)>
        callback2;
    MockFunction<void(MockResourceNodePoolListener::Action action, const std::shared_ptr<ResourceNode> &resource)>
        callback3;

    auto listener1 = MockResourceNodePoolListener::Create(
        [&callback1](MockResourceNodePoolListener::Action action, const std::shared_ptr<ResourceNode> &resource) {
            callback1.Call(action, resource);
        });
    EXPECT_EQ(pool.RegisterResourceNodePoolListener(listener1), true);

    auto listener2 = MockResourceNodePoolListener::Create(
        [&callback2](MockResourceNodePoolListener::Action action, const std::shared_ptr<ResourceNode> &resource) {
            callback2.Call(action, resource);
        });
    EXPECT_EQ(pool.RegisterResourceNodePoolListener(listener2), true);

    auto listener3 = MockResourceNodePoolListener::Create(
        [&callback3](MockResourceNodePoolListener::Action action, const std::shared_ptr<ResourceNode> &resource) {
            callback3.Call(action, resource);
        });
    EXPECT_EQ(pool.RegisterResourceNodePoolListener(listener3), true);

    EXPECT_CALL(callback1, Call(MockResourceNodePoolListener::INSERT, _)).Times(1);
    EXPECT_CALL(callback2, Call(MockResourceNodePoolListener::INSERT, _)).Times(2);
    EXPECT_CALL(callback3, Call(MockResourceNodePoolListener::INSERT, _)).Times(3);

    EXPECT_CALL(callback1, Call(MockResourceNodePoolListener::DELETE, _)).Times(1);
    EXPECT_CALL(callback2, Call(MockResourceNodePoolListener::DELETE, _)).Times(2);
    EXPECT_CALL(callback3, Call(MockResourceNodePoolListener::DELETE, _)).Times(3);

    EXPECT_EQ(pool.Insert(resource1), true);
    EXPECT_EQ(pool.Delete(EXECUTOR_INDEX1), true);
    EXPECT_EQ(pool.DeregisterResourceNodePoolListener(listener1), true);
    EXPECT_EQ(pool.Insert(resource2), true);
    EXPECT_EQ(pool.Delete(EXECUTOR_INDEX2), true);
    EXPECT_EQ(pool.DeregisterResourceNodePoolListener(listener2), true);
    EXPECT_EQ(pool.Insert(resource3), true);
    EXPECT_EQ(pool.Delete(EXECUTOR_INDEX3), true);
    EXPECT_EQ(pool.DeregisterResourceNodePoolListener(listener3), true);
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(ResourceNodePoolTest, ResourceNodePoolListenerUpdate, TestSize.Level0)
{
    auto &pool = ResourceNodePool::Instance();
    const uint64_t EXECUTOR_INDEX1 = 300;
    const uint64_t EXECUTOR_INDEX2 = 300;
    auto resource1 = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX1, true);
    auto resource2 = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX2);

    MockFunction<void(MockResourceNodePoolListener::Action action, const std::shared_ptr<ResourceNode> &resource)>
        callback;

    auto listener = MockResourceNodePoolListener::Create(
        [&callback](MockResourceNodePoolListener::Action action, const std::shared_ptr<ResourceNode> &resource) {
            callback.Call(action, resource);
        });
    EXPECT_EQ(pool.RegisterResourceNodePoolListener(listener), true);

    EXPECT_CALL(callback, Call(MockResourceNodePoolListener::INSERT, _)).Times(1);
    EXPECT_CALL(callback, Call(MockResourceNodePoolListener::UPDATE, _)).Times(1);
    EXPECT_CALL(callback, Call(MockResourceNodePoolListener::DELETE, _)).Times(1);

    EXPECT_EQ(pool.Insert(resource1), true);
    EXPECT_EQ(pool.Insert(resource2), true);
    EXPECT_EQ(pool.Delete(EXECUTOR_INDEX1), true);
    EXPECT_EQ(pool.Delete(EXECUTOR_INDEX2), true);

    EXPECT_EQ(pool.DeregisterResourceNodePoolListener(listener), true);
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(ResourceNodePoolTest, ResourceNodePoolTestDelete, TestSize.Level0)
{
    auto &pool = ResourceNodePool::Instance();
    const uint64_t EXECUTOR_INDEX1 = 300;
    const uint64_t EXECUTOR_INDEX2 = 500;
    auto resource1 = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX1);
    auto resource2 = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX2);

    auto listener1 = Common::MakeShared<MockResourceNodePoolListener>();
    EXPECT_NE(listener1, nullptr);
    EXPECT_CALL(*listener1, OnResourceNodePoolDelete(_)).Times(2);
    EXPECT_CALL(*listener1, OnResourceNodePoolInsert(_)).Times(2);
    EXPECT_TRUE(pool.RegisterResourceNodePoolListener(listener1));
    std::shared_ptr<ResourceNodePool::ResourceNodePoolListener> listener2 = nullptr;
    EXPECT_FALSE(pool.RegisterResourceNodePoolListener(listener2));

    EXPECT_TRUE(pool.Insert(resource1));
    EXPECT_TRUE(pool.Insert(resource2));
    pool.DeleteAll();

    EXPECT_TRUE(pool.DeregisterResourceNodePoolListener(listener1));
}

HWTEST_F(ResourceNodePoolTest, ResourceNodePoolTestEnumerate, TestSize.Level0)
{
    auto &pool = ResourceNodePool::Instance();
    const uint64_t EXECUTOR_INDEX1 = 300;
    const uint64_t EXECUTOR_INDEX2 = 500;
    auto resource1 = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX1);
    auto resource2 = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX2);

    auto action1 = [](const std::weak_ptr<ResourceNode> &) {
        return;
    };
    std::function<void(const std::weak_ptr<ResourceNode> &)> action2 = nullptr;
    pool.Enumerate(action2);
    pool.Enumerate(action1);
    EXPECT_TRUE(pool.Insert(resource1));
    EXPECT_TRUE(pool.Insert(resource2));
    EXPECT_EQ(pool.Select(400).lock(), nullptr);
    EXPECT_NE(pool.Select(EXECUTOR_INDEX1).lock(), nullptr);
    EXPECT_NE(pool.Select(EXECUTOR_INDEX1).lock(), nullptr);
    pool.Enumerate(action1);

    pool.DeleteAll();
}

HWTEST_F(ResourceNodePoolTest, GetResourceNodeByTypeAndRole, TestSize.Level0)
{
    auto &pool = ResourceNodePool::Instance();
    std::vector<std::weak_ptr<ResourceNode>> pinNodes;
    std::vector<std::weak_ptr<ResourceNode>> faceNodes;
    std::vector<std::weak_ptr<ResourceNode>> fingerPrintNodes;

    const uint64_t EXECUTOR_INDEX1 = 300;
    auto resource1 = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX1);
    EXPECT_EQ(pool.Insert(resource1), true);

    EXPECT_NO_THROW(pool.GetResourceNodeByTypeAndRole(AuthType::PIN, ALL_IN_ONE, faceNodes));
    EXPECT_NO_THROW(pool.GetResourceNodeByTypeAndRole(AuthType::FACE, ALL_IN_ONE, faceNodes));
    EXPECT_NO_THROW(pool.GetResourceNodeByTypeAndRole(AuthType::FINGERPRINT, ALL_IN_ONE, fingerPrintNodes));

    EXPECT_NO_THROW(pool.GetResourceNodeByTypeAndRole(AuthType::PIN, SCHEDULER, faceNodes));
    EXPECT_NO_THROW(pool.GetResourceNodeByTypeAndRole(AuthType::FACE, SCHEDULER, faceNodes));
    EXPECT_NO_THROW(pool.GetResourceNodeByTypeAndRole(AuthType::FINGERPRINT, SCHEDULER, fingerPrintNodes));

    EXPECT_NO_THROW(pool.GetResourceNodeByTypeAndRole(AuthType::PIN, COLLECTOR, faceNodes));
    EXPECT_NO_THROW(pool.GetResourceNodeByTypeAndRole(AuthType::FACE, COLLECTOR, faceNodes));
    EXPECT_NO_THROW(pool.GetResourceNodeByTypeAndRole(AuthType::FINGERPRINT, COLLECTOR, fingerPrintNodes));

    EXPECT_NO_THROW(pool.GetResourceNodeByTypeAndRole(AuthType::PIN, VERIFIER, faceNodes));
    EXPECT_NO_THROW(pool.GetResourceNodeByTypeAndRole(AuthType::FACE, VERIFIER, faceNodes));
    EXPECT_NO_THROW(pool.GetResourceNodeByTypeAndRole(AuthType::FINGERPRINT, VERIFIER, fingerPrintNodes));
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(ResourceNodePoolTest, ResourceNodePoolDeleteWithListener, TestSize.Level0)
{
    auto &pool = ResourceNodePool::Instance();
    const uint64_t EXECUTOR_INDEX = 700;
    auto resource = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX);
    ASSERT_NE(resource, nullptr);

    auto listener = Common::MakeShared<MockResourceNodePoolListener>();
    ASSERT_NE(listener, nullptr);
    EXPECT_CALL(*listener, OnResourceNodePoolInsert(_)).Times(1);
    EXPECT_CALL(*listener, OnResourceNodePoolDelete(_)).Times(1);
    EXPECT_TRUE(pool.RegisterResourceNodePoolListener(listener));

    EXPECT_TRUE(pool.Insert(resource));
    EXPECT_TRUE(pool.Delete(EXECUTOR_INDEX));

    EXPECT_TRUE(pool.DeregisterResourceNodePoolListener(listener));
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(ResourceNodePoolTest, ResourceNodePoolDeleteAllWithListener, TestSize.Level0)
{
    auto &pool = ResourceNodePool::Instance();
    const uint64_t EXECUTOR_INDEX1 = 800;
    const uint64_t EXECUTOR_INDEX2 = 900;
    auto resource1 = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX1);
    auto resource2 = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX2);
    ASSERT_NE(resource1, nullptr);
    ASSERT_NE(resource2, nullptr);

    auto listener = Common::MakeShared<MockResourceNodePoolListener>();
    ASSERT_NE(listener, nullptr);
    EXPECT_CALL(*listener, OnResourceNodePoolInsert(_)).Times(2);
    EXPECT_CALL(*listener, OnResourceNodePoolDelete(_)).Times(2);
    EXPECT_TRUE(pool.RegisterResourceNodePoolListener(listener));

    EXPECT_TRUE(pool.Insert(resource1));
    EXPECT_TRUE(pool.Insert(resource2));
    pool.DeleteAll();

    EXPECT_TRUE(pool.DeregisterResourceNodePoolListener(listener));
    ResourceNodePool::Instance().DeleteAll();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
