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

#include "load_mode_handler_default_test.h"

#include "load_mode_handler_default.h"

#include "mock_iuser_auth_interface.h"
#include "system_param_manager.h"
#include "user_idm_database_impl.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void LoadModeHandlerDefaultTest::SetUpTestCase()
{
}

void LoadModeHandlerDefaultTest::TearDownTestCase()
{
}

void LoadModeHandlerDefaultTest::SetUp()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

void LoadModeHandlerDefaultTest::TearDown()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

/**
 * @tc.name: OnCredentialUpdated_001
 * @tc.desc: Test OnCredentialUpdated with non-COMPANION_DEVICE authType
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, OnCredentialUpdated_001, TestSize.Level0)
{
    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    // Test with PIN authType (not COMPANION_DEVICE)
    EXPECT_NO_THROW(handler->OnCredentialUpdated(AuthType::PIN));
    EXPECT_NO_THROW(handler->OnCredentialUpdated(AuthType::FACE));
    EXPECT_NO_THROW(handler->OnCredentialUpdated(AuthType::FINGERPRINT));
}

/**
 * @tc.name: OnCredentialUpdated_002
 * @tc.desc: Test OnCredentialUpdated with COMPANION_DEVICE authType, no credentials
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, OnCredentialUpdated_002, TestSize.Level0)
{
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);

    // Mock GetCredential to return empty credentials
    auto fillEmptyCreds = [](std::vector<HdiCredentialInfo> &list) {
        std::vector<HdiCredentialInfo> infos = {};
        list.swap(infos);
    };
    EXPECT_CALL(*mockHdi, GetCredential(_, static_cast<int32_t>(AuthType::COMPANION_DEVICE), _))
        .WillRepeatedly(DoAll(WithArg<2>(fillEmptyCreds), Return(SUCCESS)));

    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    // Test with COMPANION_DEVICE authType
    EXPECT_NO_THROW(handler->OnCredentialUpdated(AuthType::COMPANION_DEVICE));
}

/**
 * @tc.name: OnCredentialUpdated_003
 * @tc.desc: Test OnCredentialUpdated with COMPANION_DEVICE authType, has credentials
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, OnCredentialUpdated_003, TestSize.Level0)
{
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);

    // Mock GetCredential to return credentials
    auto fillCreds = [](std::vector<HdiCredentialInfo> &list) {
        std::vector<HdiCredentialInfo> infos = {};
        HdiCredentialInfo info = {
            .credentialId = 1,
            .executorIndex = 2,
            .templateId = 3,
            .authType = static_cast<HdiAuthType>(AuthType::COMPANION_DEVICE),
            .executorMatcher = 1,
            .executorSensorHint = 1,
        };
        infos.push_back(info);
        list.swap(infos);
    };
    EXPECT_CALL(*mockHdi, GetCredential(_, static_cast<int32_t>(AuthType::COMPANION_DEVICE), _))
        .WillRepeatedly(DoAll(WithArg<2>(fillCreds), Return(SUCCESS)));

    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    // Test with COMPANION_DEVICE authType
    EXPECT_NO_THROW(handler->OnCredentialUpdated(AuthType::COMPANION_DEVICE));
}

/**
 * @tc.name: OnFwkReady_001
 * @tc.desc: Test OnFwkReady sets FWK_READY_KEY parameter
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, OnFwkReady_001, TestSize.Level0)
{
    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    EXPECT_NO_THROW(handler->OnFwkReady());

    // Verify FWK_READY_KEY was set
    std::string paramVal = SystemParamManager::GetInstance().GetParam(FWK_READY_KEY, FALSE_STR);
    EXPECT_EQ(paramVal, TRUE_STR);
}

/**
 * @tc.name: OnFwkReady_002
 * @tc.desc: Test OnFwkReady with HDI failure for credential check
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, OnFwkReady_002, TestSize.Level0)
{
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);

    // Mock GetCredential to return failure
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillRepeatedly(Return(GENERAL_ERROR));

    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    EXPECT_NO_THROW(handler->OnFwkReady());
}

/**
 * @tc.name: OnFwkReady_003
 * @tc.desc: Test OnFwkReady with companion device credentials available
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, OnFwkReady_003, TestSize.Level0)
{
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);

    // Mock GetCredential to return credentials
    auto fillCreds = [](std::vector<HdiCredentialInfo> &list) {
        std::vector<HdiCredentialInfo> infos = {};
        HdiCredentialInfo info = {
            .credentialId = 1,
            .executorIndex = 2,
            .templateId = 3,
            .authType = static_cast<HdiAuthType>(AuthType::COMPANION_DEVICE),
            .executorMatcher = 1,
            .executorSensorHint = 1,
        };
        infos.push_back(info);
        list.swap(infos);
    };
    EXPECT_CALL(*mockHdi, GetCredential(_, static_cast<int32_t>(AuthType::COMPANION_DEVICE), _))
        .WillRepeatedly(DoAll(WithArg<2>(fillCreds), Return(SUCCESS)));

    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    EXPECT_NO_THROW(handler->OnFwkReady());
}

/**
 * @tc.name: StartSubscribe_001
 * @tc.desc: Test StartSubscribe basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, StartSubscribe_001, TestSize.Level0)
{
    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    EXPECT_NO_THROW(handler->StartSubscribe());
    // Call again to test idempotency
    EXPECT_NO_THROW(handler->StartSubscribe());
}

/**
 * @tc.name: AnyUserHasCompanionDeviceCredential_001
 * @tc.desc: Test AnyUserHasCompanionDeviceCredential with empty credentials
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, AnyUserHasCompanionDeviceCredential_001, TestSize.Level0)
{
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);

    // Mock GetCredential to return empty credentials
    auto fillEmptyCreds = [](std::vector<HdiCredentialInfo> &list) {
        std::vector<HdiCredentialInfo> infos = {};
        list.swap(infos);
    };
    EXPECT_CALL(*mockHdi, GetCredential(_, static_cast<int32_t>(AuthType::COMPANION_DEVICE), _))
        .WillRepeatedly(DoAll(WithArg<2>(fillEmptyCreds), Return(SUCCESS)));

    LoadModeHandlerDefault handler;
    // Access private method using -Dprivate=public flag
    auto result = handler.AnyUserHasCompanionDeviceCredential();
    EXPECT_TRUE(result.has_value());
    EXPECT_FALSE(result.value());
}

/**
 * @tc.name: AnyUserHasCompanionDeviceCredential_002
 * @tc.desc: Test AnyUserHasCompanionDeviceCredential with credentials
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, AnyUserHasCompanionDeviceCredential_002, TestSize.Level0)
{
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);

    // Mock GetCredential to return credentials
    auto fillCreds = [](std::vector<HdiCredentialInfo> &list) {
        std::vector<HdiCredentialInfo> infos = {};
        HdiCredentialInfo info = {
            .credentialId = 1,
            .executorIndex = 2,
            .templateId = 3,
            .authType = static_cast<HdiAuthType>(AuthType::COMPANION_DEVICE),
            .executorMatcher = 1,
            .executorSensorHint = 1,
        };
        infos.push_back(info);
        list.swap(infos);
    };
    EXPECT_CALL(*mockHdi, GetCredential(_, static_cast<int32_t>(AuthType::COMPANION_DEVICE), _))
        .WillRepeatedly(DoAll(WithArg<2>(fillCreds), Return(SUCCESS)));

    LoadModeHandlerDefault handler;
    auto result = handler.AnyUserHasCompanionDeviceCredential();
    EXPECT_TRUE(result.has_value());
    EXPECT_FALSE(result.value());
}

/**
 * @tc.name: AnyUserHasCompanionDeviceCredential_003
 * @tc.desc: Test AnyUserHasCompanionDeviceCredential with HDI failure
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, AnyUserHasCompanionDeviceCredential_003, TestSize.Level0)
{
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);

    // Mock GetCredential to return failure
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillRepeatedly(Return(GENERAL_ERROR));

    LoadModeHandlerDefault handler;
    // With HDI failure, should continue to next user and return false (no credentials found)
    auto result = handler.AnyUserHasCompanionDeviceCredential();
    EXPECT_TRUE(result.has_value());
    EXPECT_FALSE(result.value());
}

/**
 * @tc.name: CheckStartCompanionDeviceSa_001
 * @tc.desc: Test CheckStartCompanionDeviceSa with no credentials
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, CheckStartCompanionDeviceSa_001, TestSize.Level0)
{
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);

    // Mock GetCredential to return empty credentials
    auto fillEmptyCreds = [](std::vector<HdiCredentialInfo> &list) {
        std::vector<HdiCredentialInfo> infos = {};
        list.swap(infos);
    };
    EXPECT_CALL(*mockHdi, GetCredential(_, static_cast<int32_t>(AuthType::COMPANION_DEVICE), _))
        .WillRepeatedly(DoAll(WithArg<2>(fillEmptyCreds), Return(SUCCESS)));

    LoadModeHandlerDefault handler;
    EXPECT_NO_THROW(handler.CheckStartCompanionDeviceSa());
}

/**
 * @tc.name: CheckStartCompanionDeviceSa_002
 * @tc.desc: Test CheckStartCompanionDeviceSa with credentials
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, CheckStartCompanionDeviceSa_002, TestSize.Level0)
{
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);

    // Mock GetCredential to return credentials
    auto fillCreds = [](std::vector<HdiCredentialInfo> &list) {
        std::vector<HdiCredentialInfo> infos = {};
        HdiCredentialInfo info = {
            .credentialId = 1,
            .executorIndex = 2,
            .templateId = 3,
            .authType = static_cast<HdiAuthType>(AuthType::COMPANION_DEVICE),
            .executorMatcher = 1,
            .executorSensorHint = 1,
        };
        infos.push_back(info);
        list.swap(infos);
    };
    EXPECT_CALL(*mockHdi, GetCredential(_, static_cast<int32_t>(AuthType::COMPANION_DEVICE), _))
        .WillRepeatedly(DoAll(WithArg<2>(fillCreds), Return(SUCCESS)));

    LoadModeHandlerDefault handler;
    EXPECT_NO_THROW(handler.CheckStartCompanionDeviceSa());
}

/**
 * @tc.name: OnExecutorRegistered_001
 * @tc.desc: Test OnExecutorRegistered basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, OnExecutorRegistered_001, TestSize.Level0)
{
    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    EXPECT_NO_THROW(handler->OnExecutorRegistered(AuthType::PIN, ExecutorRole::COLLECTOR));
    EXPECT_NO_THROW(handler->OnExecutorRegistered(AuthType::FACE, ExecutorRole::VERIFIER));
    EXPECT_NO_THROW(handler->OnExecutorRegistered(AuthType::FINGERPRINT, ExecutorRole::ALL_IN_ONE));
}

/**
 * @tc.name: OnExecutorUnregistered_001
 * @tc.desc: Test OnExecutorUnregistered basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, OnExecutorUnregistered_001, TestSize.Level0)
{
    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    EXPECT_NO_THROW(handler->OnExecutorUnregistered(AuthType::PIN, ExecutorRole::COLLECTOR));
    EXPECT_NO_THROW(handler->OnExecutorUnregistered(AuthType::FACE, ExecutorRole::VERIFIER));
}

/**
 * @tc.name: OnPinAuthServiceReady_001
 * @tc.desc: Test OnPinAuthServiceReady basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, OnPinAuthServiceReady_001, TestSize.Level0)
{
    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    EXPECT_NO_THROW(handler->OnPinAuthServiceReady());
}

/**
 * @tc.name: OnPinAuthServiceStop_001
 * @tc.desc: Test OnPinAuthServiceStop basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, OnPinAuthServiceStop_001, TestSize.Level0)
{
    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    EXPECT_NO_THROW(handler->OnPinAuthServiceStop());
}

/**
 * @tc.name: OnDriverStart_001
 * @tc.desc: Test OnDriverStart basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, OnDriverStart_001, TestSize.Level0)
{
    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    EXPECT_NO_THROW(handler->OnDriverStart());
}

/**
 * @tc.name: OnDriverStop_001
 * @tc.desc: Test OnDriverStop basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, OnDriverStop_001, TestSize.Level0)
{
    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    EXPECT_NO_THROW(handler->OnDriverStop());
}

/**
 * @tc.name: SubscribeCredentialUpdatedListener_001
 * @tc.desc: Test SubscribeCredentialUpdatedListener basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, SubscribeCredentialUpdatedListener_001, TestSize.Level0)
{
    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    EXPECT_NO_THROW(handler->SubscribeCredentialUpdatedListener());
}

/**
 * @tc.name: OnCommonEventSaStart_001
 * @tc.desc: Test OnCommonEventSaStart basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, OnCommonEventSaStart_001, TestSize.Level0)
{
    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    EXPECT_NO_THROW(handler->OnCommonEventSaStart());
}

/**
 * @tc.name: StartCheckServiceReadyTimer_001
 * @tc.desc: Test StartCheckServiceReadyTimer basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, StartCheckServiceReadyTimer_001, TestSize.Level0)
{
    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    EXPECT_NO_THROW(handler->StartCheckServiceReadyTimer());
}

/**
 * @tc.name: CancelCheckServiceReadyTimer_001
 * @tc.desc: Test CancelCheckServiceReadyTimer basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, CancelCheckServiceReadyTimer_001, TestSize.Level0)
{
    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    EXPECT_NO_THROW(handler->CancelCheckServiceReadyTimer());
}

/**
 * @tc.name: TriggerAllServiceStart_001
 * @tc.desc: Test TriggerAllServiceStart basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(LoadModeHandlerDefaultTest, TriggerAllServiceStart_001, TestSize.Level0)
{
    auto handler = std::make_unique<LoadModeHandlerDefault>();
    EXPECT_NE(handler, nullptr);

    EXPECT_NO_THROW(handler->TriggerAllServiceStart());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
