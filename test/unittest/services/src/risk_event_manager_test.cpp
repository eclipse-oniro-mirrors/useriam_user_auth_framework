/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "risk_event_manager_test.h"

#include "risk_event_manager.h"

#include "securec.h"
#include "mock_iuser_auth_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void RiskEventManagerTest::SetUpTestCase()
{
}

void RiskEventManagerTest::TearDownTestCase()
{
}

void RiskEventManagerTest::SetUp()
{
}

void RiskEventManagerTest::TearDown()
{
}

HWTEST_F(RiskEventManagerTest, SetRiskEventPropertyForAuthTypeTest, TestSize.Level0)
{
    int32_t mainUserId = 100;
    int32_t inValidUserId = -1;
    EXPECT_NO_THROW(RiskEventManager::GetInstance().SetRiskEventPropertyForAuthType(mainUserId,
        AuthType::FACE, RiskEventManager::EventType::SCREENLOCK_STRONG_AUTH));
    EXPECT_NO_THROW(RiskEventManager::GetInstance().SetRiskEventPropertyForAuthType(inValidUserId,
        AuthType::FACE, RiskEventManager::EventType::SCREENLOCK_STRONG_AUTH));
    EXPECT_NO_THROW(RiskEventManager::GetInstance().SetRiskEventPropertyForAuthType(mainUserId,
        AuthType::PIN, RiskEventManager::EventType::SCREENLOCK_STRONG_AUTH));
    EXPECT_NO_THROW(RiskEventManager::GetInstance().SetRiskEventPropertyForAuthType(mainUserId,
        AuthType::PIN, RiskEventManager::EventType::UNKNOWN));
}

HWTEST_F(RiskEventManagerTest, GetAttributesTest, TestSize.Level0)
{
    int32_t mainUserId = 100;
    int32_t inValidUserId = -1;
    Attributes attributes;
    EXPECT_NO_THROW(RiskEventManager::GetInstance().SetAttributes(mainUserId, AuthType::FACE,
        RiskEventManager::EventType::SCREENLOCK_STRONG_AUTH, attributes));
    EXPECT_NO_THROW(RiskEventManager::GetInstance().SetAttributes(inValidUserId, AuthType::FACE,
        RiskEventManager::EventType::SCREENLOCK_STRONG_AUTH, attributes));
    EXPECT_NO_THROW(RiskEventManager::GetInstance().SetAttributes(mainUserId, AuthType::FACE,
        RiskEventManager::EventType::UNKNOWN, attributes));
}

HWTEST_F(RiskEventManagerTest, GetTemplateIdListTest, TestSize.Level0)
{
    int32_t mainUserId = 100;
    int32_t inValidUserId = -1;
    std::vector<uint64_t> templateIds;
    EXPECT_NO_THROW(RiskEventManager::GetInstance().GetTemplateIdList(mainUserId, AuthType::FACE,
        templateIds));
    EXPECT_NO_THROW(RiskEventManager::GetInstance().GetTemplateIdList(inValidUserId, AuthType::FACE,
        templateIds));
    EXPECT_NO_THROW(RiskEventManager::GetInstance().GetTemplateIdList(mainUserId, AuthType::PIN,
        templateIds));
    EXPECT_NO_THROW(RiskEventManager::GetInstance().GetTemplateIdList(inValidUserId, AuthType::PIN,
        templateIds));
}

HWTEST_F(RiskEventManagerTest, GetTemplateIdListTestFail, TestSize.Level0)
{
    int32_t mainUserId = 100;
    AuthType authType = PIN;
    std::vector<uint64_t> templateIds;
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();

    {
        EXPECT_CALL(*mock, GetCredential(_, _, _)).WillRepeatedly(Return(NOT_ENROLLED));
        EXPECT_NO_THROW(RiskEventManager::GetInstance().GetTemplateIdList(mainUserId, authType, templateIds));
    }

    {
        EXPECT_CALL(*mock, GetCredential(_, _, _)).WillRepeatedly(Return(1));
        EXPECT_NO_THROW(RiskEventManager::GetInstance().GetTemplateIdList(mainUserId, authType, templateIds));
    }
}

HWTEST_F(RiskEventManagerTest, SetAttributesTestFail, TestSize.Level0)
{
    int32_t mainUserId = 100;
    Attributes attributes;
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, GetCredential(_, _, _)).WillRepeatedly(Return(1));
    EXPECT_NO_THROW(RiskEventManager::GetInstance().SetAttributes(mainUserId, AuthType::FACE,
        RiskEventManager::EventType::SCREENLOCK_STRONG_AUTH, attributes));
}

HWTEST_F(RiskEventManagerTest, GetStrongAuthExtraInfoTest, TestSize.Level0)
{
    std::vector<uint8_t> extraInfo;
    int32_t mainUserId = 100;
    int32_t inValidUserId = -1;
    EXPECT_NO_THROW(RiskEventManager::GetInstance().GetStrongAuthExtraInfo(mainUserId,
        AuthType::FACE, extraInfo));
    EXPECT_NO_THROW(RiskEventManager::GetInstance().GetStrongAuthExtraInfo(inValidUserId,
        AuthType::FACE, extraInfo));
}

HWTEST_F(RiskEventManagerTest, HandleStrongAuthEventTest, TestSize.Level0)
{
    int32_t mainUserId = 100;
    int32_t inValidUserId = -1;
    EXPECT_NO_THROW(RiskEventManager::GetInstance().HandleStrongAuthEvent(mainUserId));
    EXPECT_NO_THROW(RiskEventManager::GetInstance().HandleStrongAuthEvent(inValidUserId));
}

HWTEST_F(RiskEventManagerTest, SyncRiskEventsTest, TestSize.Level0)
{
    auto instance = RiskEventManager::GetInstance();
    EXPECT_NO_THROW(instance.SyncRiskEvents());
    EXPECT_NO_THROW(instance.OnScreenLock());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS