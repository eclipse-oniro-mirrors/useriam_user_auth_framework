/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "service_init_manager_test.h"
#include "service_init_manager.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

using namespace testing;
using namespace testing::ext;

void ServiceInitManagerTest::SetUpTestCase()
{
}

void ServiceInitManagerTest::TearDownTestCase()
{
}

void ServiceInitManagerTest::SetUp()
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.OnIdmServiceStop();
    manager.OnCoAuthServiceStop();
    manager.OnUserAuthServiceStop();
}

void ServiceInitManagerTest::TearDown()
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.OnIdmServiceStop();
    manager.OnCoAuthServiceStop();
    manager.OnUserAuthServiceStop();
}

HWTEST_F(ServiceInitManagerTest, ServiceInitMangagerOnStartStopTest, TestSize.Level0)
{
    EXPECT_NO_THROW({
        ServiceInitManager::GetInstance().OnIdmServiceStart();
        ServiceInitManager::GetInstance().OnIdmServiceStop();
        ServiceInitManager::GetInstance().OnCoAuthServiceStart();
        ServiceInitManager::GetInstance().OnCoAuthServiceStart();
        ServiceInitManager::GetInstance().OnUserAuthServiceStart();
        ServiceInitManager::GetInstance().OnUserAuthServiceStop();
    });
}

HWTEST_F(ServiceInitManagerTest, OnCoAuthServiceStop_001, TestSize.Level0)
{
    EXPECT_NO_THROW(ServiceInitManager::GetInstance().OnCoAuthServiceStop());
}

HWTEST_F(ServiceInitManagerTest, OnCoAuthServiceStop_002, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.OnCoAuthServiceStart();
    EXPECT_TRUE(manager.isCoAuthServiceStart_);

    manager.OnCoAuthServiceStop();
    EXPECT_FALSE(manager.isCoAuthServiceStart_);
}

HWTEST_F(ServiceInitManagerTest, OnCoAuthServiceStop_003, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.OnIdmServiceStart();
    manager.OnUserAuthServiceStart();
    manager.OnCoAuthServiceStart();

    EXPECT_TRUE(manager.isIdmServiceStart_);
    EXPECT_TRUE(manager.isCoAuthServiceStart_);
    EXPECT_TRUE(manager.isUserAuthServiceStart_);

    EXPECT_NO_THROW(manager.OnCoAuthServiceStop());
    EXPECT_FALSE(manager.isCoAuthServiceStart_);
    EXPECT_TRUE(manager.isIdmServiceStart_);
    EXPECT_TRUE(manager.isUserAuthServiceStart_);
}

HWTEST_F(ServiceInitManagerTest, OnCoAuthServiceStop_004, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.OnCoAuthServiceStart();
    EXPECT_TRUE(manager.isCoAuthServiceStart_);

    manager.OnIdmServiceStop();
    manager.OnUserAuthServiceStop();

    EXPECT_FALSE(manager.isIdmServiceStart_);
    EXPECT_FALSE(manager.isUserAuthServiceStart_);

    EXPECT_NO_THROW(manager.OnCoAuthServiceStop());
    EXPECT_FALSE(manager.isCoAuthServiceStart_);
    EXPECT_FALSE(manager.isIdmServiceStart_);
    EXPECT_FALSE(manager.isUserAuthServiceStart_);
}

HWTEST_F(ServiceInitManagerTest, OnCoAuthServiceStop_005, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.OnCoAuthServiceStart();
    EXPECT_TRUE(manager.isCoAuthServiceStart_);

    EXPECT_NO_THROW(manager.OnCoAuthServiceStop());
    EXPECT_NO_THROW(manager.OnCoAuthServiceStop());
    EXPECT_NO_THROW(manager.OnCoAuthServiceStop());

    EXPECT_FALSE(manager.isCoAuthServiceStart_);
}

HWTEST_F(ServiceInitManagerTest, OnCoAuthServiceStop_006, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.OnIdmServiceStart();
    manager.OnCoAuthServiceStart();
    manager.OnUserAuthServiceStart();

    EXPECT_TRUE(manager.isIdmServiceStart_);
    EXPECT_TRUE(manager.isCoAuthServiceStart_);
    EXPECT_TRUE(manager.isUserAuthServiceStart_);

    EXPECT_NO_THROW(manager.OnCoAuthServiceStop());
    EXPECT_NO_THROW(manager.OnCoAuthServiceStop());
    EXPECT_NO_THROW(manager.OnUserAuthServiceStop());
    EXPECT_NO_THROW(manager.OnIdmServiceStop());

    EXPECT_FALSE(manager.isCoAuthServiceStart_);
    EXPECT_FALSE(manager.isIdmServiceStart_);
    EXPECT_FALSE(manager.isUserAuthServiceStart_);
}

HWTEST_F(ServiceInitManagerTest, CheckAllServiceStart_001, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    EXPECT_FALSE(manager.isIdmServiceStart_);
    EXPECT_FALSE(manager.isCoAuthServiceStart_);
    EXPECT_FALSE(manager.isUserAuthServiceStart_);

    manager.OnIdmServiceStart();
    EXPECT_TRUE(manager.isIdmServiceStart_);
    EXPECT_FALSE(manager.isCoAuthServiceStart_);
    EXPECT_FALSE(manager.isUserAuthServiceStart_);

    EXPECT_NO_THROW(manager.CheckAllServiceStart());
    EXPECT_TRUE(manager.isIdmServiceStart_);
    EXPECT_FALSE(manager.isCoAuthServiceStart_);
    EXPECT_FALSE(manager.isUserAuthServiceStart_);
}

HWTEST_F(ServiceInitManagerTest, CheckAllServiceStart_002, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.OnIdmServiceStart();
    manager.OnCoAuthServiceStart();
    manager.OnUserAuthServiceStart();

    EXPECT_TRUE(manager.isIdmServiceStart_);
    EXPECT_TRUE(manager.isCoAuthServiceStart_);
    EXPECT_TRUE(manager.isUserAuthServiceStart_);

    EXPECT_NO_THROW(manager.CheckAllServiceStart());

    EXPECT_TRUE(manager.isIdmServiceStart_);
    EXPECT_TRUE(manager.isCoAuthServiceStart_);
    EXPECT_TRUE(manager.isUserAuthServiceStart_);
}

HWTEST_F(ServiceInitManagerTest, CheckAllServiceStart_003, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.OnIdmServiceStart();
    manager.OnCoAuthServiceStart();
    manager.OnUserAuthServiceStart();

    EXPECT_NO_THROW(manager.CheckAllServiceStart());
    EXPECT_NO_THROW(manager.CheckAllServiceStart());
    EXPECT_NO_THROW(manager.CheckAllServiceStart());

    EXPECT_TRUE(manager.isIdmServiceStart_);
    EXPECT_TRUE(manager.isCoAuthServiceStart_);
    EXPECT_TRUE(manager.isUserAuthServiceStart_);
}

HWTEST_F(ServiceInitManagerTest, CheckAllServiceStart_004, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();

    manager.OnIdmServiceStart();
    EXPECT_NO_THROW(manager.CheckAllServiceStart());

    manager.OnUserAuthServiceStart();
    EXPECT_NO_THROW(manager.CheckAllServiceStart());

    manager.OnCoAuthServiceStart();
    EXPECT_NO_THROW(manager.CheckAllServiceStart());

    EXPECT_TRUE(manager.isIdmServiceStart_);
    EXPECT_TRUE(manager.isCoAuthServiceStart_);
    EXPECT_TRUE(manager.isUserAuthServiceStart_);
}

HWTEST_F(ServiceInitManagerTest, CheckAllServiceStart_005, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.OnIdmServiceStart();
    manager.OnCoAuthServiceStart();
    manager.OnUserAuthServiceStart();

    EXPECT_NO_THROW(manager.CheckAllServiceStart());

    manager.OnIdmServiceStop();
    EXPECT_NO_THROW(manager.CheckAllServiceStop());

    manager.OnCoAuthServiceStop();
    EXPECT_NO_THROW(manager.CheckAllServiceStop());

    manager.OnUserAuthServiceStop();
    EXPECT_NO_THROW(manager.CheckAllServiceStop());

    EXPECT_FALSE(manager.isIdmServiceStart_);
    EXPECT_FALSE(manager.isCoAuthServiceStart_);
    EXPECT_FALSE(manager.isUserAuthServiceStart_);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS