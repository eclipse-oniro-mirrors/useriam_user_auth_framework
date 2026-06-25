/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "user_auth_service_test.h"

#include <future>

#include "iam_common_defines.h"
#include "iam_ptr.h"

#include "executor_messenger_service.h"
#include "mock_event_listener.h"
#include "mock_context.h"
#include "mock_iuser_auth_interface.h"
#include "mock_ipc_common.h"
#include "mock_modal_callback.h"
#include "mock_user_access_ctrl_callback.h"
#include "mock_user_auth_callback.h"
#include "mock_user_auth_service.h"
#include "mock_resource_node.h"
#include "mock_widget_callback_interface.h"
#include "mock_remote_auth_callback.h"
#include "resource_node_pool.h"
#include "user_auth_service.h"
#include "user_auth_helper.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

namespace {
constexpr uint32_t INVALID_PIN_ALGO_TYPE = 100;
constexpr int32_t INVALID_GLOBAL_CONFIG_TYPE = 100;
constexpr int32_t PIN_ALGO_AES_HDI_TYPE = 3;
constexpr int32_t PIN_ALGO_SM4_HDI_TYPE = 4;
constexpr int32_t TEST_USER_ID_1 = 100;
constexpr int32_t TEST_USER_ID_2 = 101;
constexpr size_t TEST_USER_IDS_SIZE = 2;
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetGlobalConfigParam004, TestSize.Level0)
{
    UserAuthService service;
    IpcGlobalConfigParam param = {};
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::CHECK_PERMISSION_FAILED);

    IpcCommon::AddPermission(ENTERPRISE_DEVICE_MGR);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);

    param.type = PIN_ALGO_TYPE;
    param.value.pinAlgoType = PinEncrypAlgoType::AES_GCM;
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.authTypes.push_back(FACE);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.authTypes.clear();
    param.authTypes.push_back(PIN);
    param.authTypes.push_back(FACE);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.authTypes.clear();
    param.authTypes.push_back(PIN);
    param.value.pinAlgoType = INVALID_PIN_ALGO_TYPE;
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.value.pinAlgoType = PinEncrypAlgoType::AES_GCM;
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::SUCCESS);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, SetGlobalConfigParam(_)).Times(1);
    ON_CALL(*mockHdi, SetGlobalConfigParam)
        .WillByDefault(
            [](const HdiGlobalConfigParam &param) {
                EXPECT_EQ(param.type, PIN_ALGO_AES_HDI_TYPE);
                return HDF_SUCCESS;
            }
        );
    EXPECT_EQ(service.SetGlobalConfigParam(param), HDF_SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetGlobalConfigParam005, TestSize.Level0)
{
    UserAuthService service;
    IpcGlobalConfigParam param = {};
    IpcCommon::AddPermission(ENTERPRISE_DEVICE_MGR);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);

    param.type = PIN_ALGO_TYPE;
    param.authTypes.push_back(PIN);
    param.value.pinAlgoType = PinEncrypAlgoType::SM4;
    param.userIds.push_back(TEST_USER_ID_1);
    param.userIds.push_back(TEST_USER_ID_2);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::SUCCESS);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, SetGlobalConfigParam(_)).Times(1);
    ON_CALL(*mockHdi, SetGlobalConfigParam)
        .WillByDefault(
            [](const HdiGlobalConfigParam &param) {
                EXPECT_EQ(param.type, PIN_ALGO_SM4_HDI_TYPE);
                EXPECT_EQ(param.userIds.size(), TEST_USER_IDS_SIZE);
                return HDF_SUCCESS;
            }
        );
    EXPECT_EQ(service.SetGlobalConfigParam(param), HDF_SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetGlobalConfigParam006, TestSize.Level0)
{
    UserAuthService service;
    IpcGlobalConfigParam param = {};
    IpcCommon::AddPermission(ENTERPRISE_DEVICE_MGR);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);

    param.type = PIN_ALGO_TYPE;
    param.authTypes.push_back(PIN);
    param.value.pinAlgoType = PinEncrypAlgoType::AES_GCM;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, SetGlobalConfigParam(_)).Times(1);
    ON_CALL(*mockHdi, SetGlobalConfigParam)
        .WillByDefault(
            [](const HdiGlobalConfigParam &param) {
                return HDF_FAILURE;
            }
        );
    EXPECT_EQ(service.SetGlobalConfigParam(param), HDF_FAILURE);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterRemoteAuthCallback001, TestSize.Level0)
{
    UserAuthService service;
    sptr<IRemoteAuthCallback> testCallback = nullptr;
    EXPECT_EQ(service.RegisterRemoteAuthCallback(testCallback), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterRemoteAuthCallback002, TestSize.Level0)
{
    UserAuthService service;
    sptr<MockRemoteAuthCallback> mockCallback = new (std::nothrow) MockRemoteAuthCallback();
    EXPECT_NE(mockCallback, nullptr);

    EXPECT_EQ(service.RegisterRemoteAuthCallback(mockCallback), ResultCode::CHECK_SYSTEM_APP_FAILED);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterRemoteAuthCallback003, TestSize.Level0)
{
    UserAuthService service;
    sptr<MockRemoteAuthCallback> mockCallback = new (std::nothrow) MockRemoteAuthCallback();
    EXPECT_NE(mockCallback, nullptr);

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.RegisterRemoteAuthCallback(mockCallback), ResultCode::CHECK_SYSTEM_APP_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterRemoteAuthCallback004, TestSize.Level0)
{
    UserAuthService service;
    sptr<MockRemoteAuthCallback> mockCallback = new (std::nothrow) MockRemoteAuthCallback();
    EXPECT_NE(mockCallback, nullptr);

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.RegisterRemoteAuthCallback(mockCallback), ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceUnregisterRemoteAuthCallback001, TestSize.Level0)
{
    UserAuthService service;
    EXPECT_EQ(service.UnregisterRemoteAuthCallback(), ResultCode::CHECK_SYSTEM_APP_FAILED);

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.UnregisterRemoteAuthCallback(), ResultCode::CHECK_SYSTEM_APP_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceUnregisterRemoteAuthCallback002, TestSize.Level0)
{
    UserAuthService service;
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);

    sptr<MockRemoteAuthCallback> mockCallback = new (std::nothrow) MockRemoteAuthCallback();
    EXPECT_NE(mockCallback, nullptr);
    EXPECT_EQ(service.RegisterRemoteAuthCallback(mockCallback), ResultCode::CHECK_PERMISSION_FAILED);
    EXPECT_EQ(service.UnregisterRemoteAuthCallback(), ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
