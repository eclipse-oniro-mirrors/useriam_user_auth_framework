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
#include "hdi_type_aliases.h"
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
#include "resource_node_pool.h"
#include "user_auth_service.h"
#include "user_auth_helper.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_SingleFaceFullscreen_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
            }
        );
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    para.widgetParam = widgetParam;
    EXPECT_EQ(service->CheckSkipLockedBiometricAuth(para, validType), LOCKED);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(1));
    MockUserAuthEngine::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_SingleFingerprintFullscreen_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::FINGERPRINT},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(validTypeList.size(), 2);
    MockUserAuthEngine::Holder::GetInstance().Reset();
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthTypeOnly_EmptyCheckedTypes_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> emptyCheckedTypes = {};
    std::set<AuthType> onlyContainTypes = {AuthType::FACE, AuthType::FINGERPRINT};
    EXPECT_TRUE(service.CheckAuthTypeOnly(emptyCheckedTypes, onlyContainTypes));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthTypeOnly_EmptyOnlyContainTypes_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> checkedTypes = {AuthType::FACE};
    std::set<AuthType> emptyOnlyContainTypes = {};
    EXPECT_FALSE(service.CheckAuthTypeOnly(checkedTypes, emptyOnlyContainTypes));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthTypeOnly_BothEmpty_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> emptyCheckedTypes = {};
    std::set<AuthType> emptyOnlyContainTypes = {};
    EXPECT_TRUE(service.CheckAuthTypeOnly(emptyCheckedTypes, emptyOnlyContainTypes));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_NoFaceWithCompanionAndFinger_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::FINGERPRINT, AuthType::PRIVATE_PIN};
    std::vector<AuthType> validAuthTypeList = {AuthType::FINGERPRINT, AuthType::COMPANION_DEVICE, AuthType::PIN};
    EXPECT_TRUE(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_NoFingerWithCompanionAndFace_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::FACE, AuthType::PRIVATE_PIN};
    std::vector<AuthType> validAuthTypeList = {AuthType::FACE, AuthType::COMPANION_DEVICE, AuthType::PIN};
    EXPECT_TRUE(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_NoFaceAndFingerWithCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::PRIVATE_PIN};
    std::vector<AuthType> validAuthTypeList = {AuthType::COMPANION_DEVICE, AuthType::PIN};
    EXPECT_TRUE(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_Size3NotOnlyFaceFinger_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FACE, AuthType::FINGERPRINT, AuthType::PIN};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    ContextFactory::AuthWidgetContextPara para = {};
    para.authTypeList = authParam.authTypes;
    para.widgetParam = widgetParam;
    int32_t ret = service.CheckAuthWidgetParam(para);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnWithPinAndOther_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::PIN, AuthType::FACE},
        .authTrustLevel = ATL2,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::PIN));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
            validTypes.push_back(static_cast<int32_t>(AuthType::PIN));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
            validTypes.push_back(static_cast<int32_t>(AuthType::PIN));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NotFullscreenSingleFaceOrFinger_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
        .skipLockedBiometricAuth = false,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(validTypeList.size(), 2);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 鐞涖儱鍘朇heckAuthWidgetType缂佸嫬鎮?: PIN+PRIVATE_PIN閸愯尙鐛婇崷鐑樻珯
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_PinAndPrivatePin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::PIN, AuthType::PRIVATE_PIN};
    int32_t ret = service.CheckAuthWidgetType(authTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

// 鐞涖儱鍘朇heckAuthWidgetType缂佸嫬鎮?: PIN+PRIVATE_PIN+COMPANION_DEVICE娑撳鍣搁崘鑼崐閸︾儤娅?
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_PinPrivatePinCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::PIN, AuthType::PRIVATE_PIN, AuthType::COMPANION_DEVICE};
    int32_t ret = service.CheckAuthWidgetType(authTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

// 鐞涖儱鍘朇heckValidSolution缂佸嫬鎮?: navBtn闂堢偟鈹?+ validType={FINGERPRINT}閸楁洜琚崹?
// 娑撴艾濮熼柅鏄忕帆閿涙艾宕熺猾璇茬€稦INGERPRINT鐏炵偘绨瑊FACE,FINGER,COMPANION}閿涘奔绗夋潻鏂挎礀INVALID
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_SingleFingerprintWithNavBtn_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::FINGERPRINT},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 鐞涖儱鍘朇heckValidSolution缂佸嫬鎮?: navBtn闂堢偟鈹?+ validType={FACE, COMPANION} + FULLSCREEN
// 娑撴艾濮熼柅鏄忕帆閿涙ACE+COMPANION鐏炵偘绨瑊FACE,FINGER,COMPANION}娴ｅ棔绗夐弰顖欑矌COMPANION閿涘瓗ULLSCREEN濡€崇础鏉╂柨娲朓NVALID
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_FaceCompanionFullscreen_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return SUCCESS;
        });
    para.authTypeList = authParam.authTypes;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    int32_t ret = service.CheckValidSolution(para, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 鐞涖儱鍘朇heckValidSolution缂佸嫬鎮?0: navBtn闂堢偟鈹?+ validType={FACE, FINGER, COMPANION} + FULLSCREEN
// 娑撴艾濮熼柅鏄忕帆閿涙矮绗佺猾璇茬€风仦鐐扮艾{FACE,FINGER,COMPANION}娴ｅ棔绗夐弰顖欑矌COMPANION閿涘瓗ULLSCREEN濡€崇础鏉╂柨娲朓NVALID
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_ThreeTypesFullscreen_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT, AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 鐞涖儱鍘朇heckPrivatePinEnroll缂佸嫬鎮?: validType={FACE, COMPANION} (size=2)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_SizeTwoFaceCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::FACE);
    validAuthTypeList.push_back(AuthType::COMPANION_DEVICE);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

// 鐞涖儱鍘朇heckPrivatePinEnroll缂佸嫬鎮?: validType={FINGERPRINT, COMPANION} (size=2)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_SizeTwoFingerCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::FINGERPRINT);
    validAuthTypeList.push_back(AuthType::COMPANION_DEVICE);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

// 鐞涖儱鍘朇heckPrivatePinEnroll缂佸嫬鎮?: validType={COMPANION, PIN} (size=2)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_SizeTwoCompanionPin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::COMPANION_DEVICE);
    validAuthTypeList.push_back(AuthType::PIN);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

// 鐞涖儱鍘朇heckAuthWidgetParam缂佸嫬鎮?: authTypes={FINGERPRINT, PIN}, navBtn=""
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_SizeTwoFingerPin_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FINGERPRINT, AuthType::PIN};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    ContextFactory::AuthWidgetContextPara para = {};
    para.authTypeList = authParam.authTypes;
    para.widgetParam = widgetParam;
    int32_t ret = service.CheckAuthWidgetParam(para);
    EXPECT_EQ(ret, SUCCESS);
}

// 鐞涖儱鍘朇heckAuthWidgetParam缂佸嫬鎮?: authTypes={FACE, COMPANION}, navBtn=""
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_SizeTwoFaceCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FACE, AuthType::COMPANION_DEVICE};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    ContextFactory::AuthWidgetContextPara para = {};
    para.authTypeList = authParam.authTypes;
    para.widgetParam = widgetParam;
    int32_t ret = service.CheckAuthWidgetParam(para);
    EXPECT_EQ(ret, SUCCESS);
}

// 鐞涖儱鍘朇heckAuthWidgetParam缂佸嫬鎮?: authTypes={FACE, PIN, COMPANION}, navBtn=""
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_SizeThreeFacePinCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FACE, AuthType::PIN, AuthType::COMPANION_DEVICE};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    ContextFactory::AuthWidgetContextPara para = {};
    para.authTypeList = authParam.authTypes;
    para.widgetParam = widgetParam;
    int32_t ret = service.CheckAuthWidgetParam(para);
    EXPECT_EQ(ret, SUCCESS);
}

// 鐞涖儱鍘朇heckAuthWidgetParam缂佸嫬鎮?: authTypes={FINGERPRINT, PIN, COMPANION}, navBtn=""
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_SizeThreeFingerPinCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FINGERPRINT, AuthType::PIN, AuthType::COMPANION_DEVICE};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    ContextFactory::AuthWidgetContextPara para = {};
    para.authTypeList = authParam.authTypes;
    para.widgetParam = widgetParam;
    int32_t ret = service.CheckAuthWidgetParam(para);
    EXPECT_EQ(ret, SUCCESS);
}

// 鐞涖儱鍘朇heckAuthWidgetType缂佸嫬鎮?: 閺冪嚛IN閵嗕焦妫RIVATE_PIN閵嗕焦妫OMPANION閿涘牆鐔€绾偓閸︾儤娅欓敍?
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_BasicFaceOrFinger_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::FACE};
    int32_t ret = service.CheckAuthWidgetType(authTypeList);
    EXPECT_EQ(ret, SUCCESS);
}

// 鐞涖儱鍘朇heckAuthWidgetType缂佸嫬鎮?: 娴犲尙RIVATE_PIN
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_OnlyPrivatePin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::PRIVATE_PIN};
    int32_t ret = service.CheckAuthWidgetType(authTypeList);
    EXPECT_EQ(ret, SUCCESS);
}

// 鐞涖儱鍘朇heckAuthWidgetType缂佸嫬鎮?: 娴犲尙IN
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_OnlyPin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::PIN};
    int32_t ret = service.CheckAuthWidgetType(authTypeList);
    EXPECT_EQ(ret, SUCCESS);
}

// 鐞涖儱鍘朇heckPrivatePinEnroll缂佸嫬鎮?: validType={COMPANION, PIN} (size=2, 閺冪嚋ACE/FINGER)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_SizeTwoCompanionPin_002, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::COMPANION_DEVICE);
    validAuthTypeList.push_back(AuthType::PIN);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

// 鐞涖儱鍘朇heckAuthWidgetParam鏉堝湱鏅? authTypes={PIN, FACE, FINGERPRINT}妞ゅ搫绨稉宥呮倱
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_SizeThreeDifferentOrder_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::PIN, AuthType::FACE, AuthType::FINGERPRINT};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    ContextFactory::AuthWidgetContextPara para = {};
    para.authTypeList = authParam.authTypes;
    para.widgetParam = widgetParam;
    int32_t ret = service.CheckAuthWidgetParam(para);
    EXPECT_EQ(ret, SUCCESS);
}

// 鐞涖儱鍘朇heckValidSolution缂佸嫬鎮?5: navBtn.empty=true + validType={FINGERPRINT} + FULLSCREEN
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnEmptyFingerprintFullscreen_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::FINGERPRINT},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 鐞涖儱鍘朇heckValidSolution缂佸嫬鎮?6: navBtn.empty=true + validType={COMPANION} + FULLSCREEN
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnEmptyCompanionFullscreen_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 鐞涖儱鍘朇heckAuthWidgetParam: authTypes={FACE, FINGERPRINT, PIN}閻ㄥ嫬鍙炬禒鏍ㄥ笓閸掓绮嶉崥?
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_SizeThreeAllPermutations_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    // 濞村鐦幍鈧張澶婂讲閼崇晫娈戦幒鎺戝灙妞ゅ搫绨?
    authParam.authTypes = {AuthType::FINGERPRINT, AuthType::PIN, AuthType::FACE};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    ContextFactory::AuthWidgetContextPara para = {};
    para.authTypeList = authParam.authTypes;
    para.widgetParam = widgetParam;
    int32_t ret = service.CheckAuthWidgetParam(para);
    EXPECT_EQ(ret, SUCCESS);
}

// 鐞涖儱鍘朇heckAuthWidgetParam: navBtn闂堢偟鈹栭崷鐑樻珯閻ㄥ嫬鍙炬禒鏍矋閸?
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_NavBtnNotEmpty_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FACE, AuthType::FINGERPRINT, AuthType::COMPANION_DEVICE};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "nav_btn";
    ContextFactory::AuthWidgetContextPara para = {};
    para.authTypeList = authParam.authTypes;
    para.widgetParam = widgetParam;
    int32_t ret = service.CheckAuthWidgetParam(para);
    EXPECT_EQ(ret, SUCCESS);
}

// 鐞涖儱鍘朇heckPrivatePinEnroll: validType.size > 3閻ㄥ嫭鍎忛崘?
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_SizeFour_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::FINGERPRINT);
    validAuthTypeList.push_back(AuthType::FACE);
    validAuthTypeList.push_back(AuthType::COMPANION_DEVICE);
    validAuthTypeList.push_back(AuthType::PIN);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

// 鐞涖儱鍘朇heckValidSolution: navBtn.empty=true + validType={PIN} (閸楁洜琚崹濠窱N)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnEmptySinglePin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::PIN},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::PIN));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 鐞涖儱鍘朇heckValidSolution: navBtn.empty=true + validType={FACE, FINGERPRINT} + DIALOG
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnEmptyFaceFingerDialog_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 鐟曞棛娲婄粭?074鐞涘矉绱癶asCompanionDevice=true && hasPrivatePin=true (hasPin=false)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_CompanionWithPrivatePin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypes = {AuthType::COMPANION_DEVICE, AuthType::PRIVATE_PIN};
    int32_t ret = service.CheckAuthWidgetType(authTypes);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

// 鐟曞棛娲婄粭?074鐞涘矉绱癶asCompanionDevice=true && hasPin=true (hasPrivatePin=false)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_CompanionWithPin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypes = {AuthType::COMPANION_DEVICE, AuthType::PIN};
    int32_t ret = service.CheckAuthWidgetType(authTypes);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

// 鐟曞棛娲婄粭?118鐞涘矉绱皏alidType.size==3 娴?hasFace=false
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_ThreeTypesNoFace_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::PRIVATE_PIN};
    std::vector<AuthType> validAuthTypeList = {
        AuthType::FINGERPRINT,
        AuthType::COMPANION_DEVICE,
        AuthType::PIN
    };
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

// 鐟曞棛娲婄粭?118鐞涘矉绱皏alidType.size==3 娴?hasFinger=false
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_ThreeTypesNoFinger_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::PRIVATE_PIN};
    std::vector<AuthType> validAuthTypeList = {
        AuthType::FACE,
        AuthType::COMPANION_DEVICE,
        AuthType::PIN
    };
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

// 鐟曞棛娲婄粭?118鐞涘矉绱皏alidType.size==3 娴?hasCompanionDevice=false
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_ThreeTypesNoCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::PRIVATE_PIN};
    std::vector<AuthType> validAuthTypeList = {
        AuthType::FACE,
        AuthType::FINGERPRINT,
        AuthType::PIN
    };
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

// 鐟曞棛娲婄粭?179鐞涘矉绱癮uthTypes.size==2 娑撴柨褰ч崠鍛儓FACE+FINGERPRINT
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_OnlyFaceFinger_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT},
    };
    WidgetParamInner widgetParam = {
        .title = "test",
        .navigationButtonText = "",
    };
    ContextFactory::AuthWidgetContextPara para = {};
    para.authTypeList = authParam.authTypes;
    para.widgetParam = widgetParam;
    int32_t ret = service.CheckAuthWidgetParam(para);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

// 鐟曞棛娲婄粭?385鐞涘矉绱皀avigationButtonText闂堢偟鈹?娑?validType閸栧懎鎯堥崗鏈电铂缁鐎?(鐟欙箑褰?!CheckAuthTypeOnly 閸掑棙鏁?
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnWithFacePin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::PIN},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::PIN));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 鐟曞棛娲婄粭?385鐞涘矉绱皀avigationButtonText闂堢偟鈹?娑?CheckAuthTypeOnly鏉╂柨娲杢rue (閸欘亝婀丆OMPANION_DEVICE)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnOnlyCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 鐟曞棛娲婄粭?391鐞涘矉绱皐indowMode=FULLSCREEN 娑?CheckAuthTypeOnly鏉╂柨娲杅alse (娑撳秵寮х搾鐭睞CE+FINGERPRINT+COMPANION_DEVICE)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_FullscreenWithPin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::PIN},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::PIN));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 鐟曞棛娲婄粭?391鐞涘矉绱皐indowMode=FULLSCREEN 娑撴柨褰ч張濉丱MPANION_DEVICE (CheckAuthTypeOnly缁楊兛绨╂稉顏呮蒋娴犳湹璐焧rue)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_FullscreenOnlyCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 鐟曞棛娲婄粭?074鐞涘矉绱癶asCompanionDevice=true 娴?hasPin=false && hasPrivatePin=false (鏉╂柨娲朣UCCESS)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_OnlyCompanionDevice_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypes = {AuthType::COMPANION_DEVICE};
    int32_t ret = service.CheckAuthWidgetType(authTypes);
    EXPECT_EQ(ret, SUCCESS);
}

// 鐟曞棛娲婄粭?179鐞涘矉绱癮uthTypes.size==2 娴?CheckAuthTypeOnly鏉╂柨娲杅alse (娓氬顩ACE+PIN)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_SizeTwoNotOnlyFaceFinger_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {
        .authTypes = {AuthType::FACE, AuthType::PIN},
    };
    WidgetParamInner widgetParam = {
        .title = "test",
        .navigationButtonText = "",
    };
    ContextFactory::AuthWidgetContextPara para = {};
    para.authTypeList = authParam.authTypes;
    para.widgetParam = widgetParam;
    int32_t ret = service.CheckAuthWidgetParam(para);
    EXPECT_EQ(ret, SUCCESS);
}

// 鐟曞棛娲婄粭?184鐞涘矉绱癮uthTypes.size==3 娴?CheckAuthTypeOnly鏉╂柨娲杅alse (娓氬顩ACE+FINGERPRINT+PIN)
HWTEST_F(UserAuthServiceTest,
    UserAuthServiceCheckAuthWidgetParam_SizeThreeNotOnlyFaceFingerCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT, AuthType::PIN},
    };
    WidgetParamInner widgetParam = {
        .title = "test",
        .navigationButtonText = "",
    };
    ContextFactory::AuthWidgetContextPara para = {};
    para.authTypeList = authParam.authTypes;
    para.widgetParam = widgetParam;
    int32_t ret = service.CheckAuthWidgetParam(para);
    EXPECT_EQ(ret, SUCCESS);
}

// 鐟曞棛娲婄粭?385鐞涘矉绱皀avigationButtonText闂堢偟鈹?娑?validType={FACE, FINGERPRINT} (娑撳秵寮х搾铏蒋娴犺绱濇潻鏂挎礀SUCCESS)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnWithFaceFinger_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 鐟曞棛娲婄粭?385鐞涘矉绱皀avigationButtonText娑撹櫣鈹?(閻叀鐭鹃崚鍡樻暜)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnEmpty_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT, AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 鐟曞棛娲婄粭?391鐞涘矉绱皐indowMode != FULLSCREEN (閻叀鐭鹃崚鍡樻暜)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NonFullscreen_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT, AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth001, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    AuthParamInner authParam = {};
    WidgetParamInner widgetParam = {};
    std::vector<AuthType> validType;
    validType.emplace_back(PIN);
    authParam.skipLockedBiometricAuth = false;
    int32_t userId = 110;
    ContextFactory::AuthWidgetContextPara para;
    para.userId = userId;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillRepeatedly(Return(HDF_SUCCESS));
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(1, PIN, COLLECTOR);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    para.widgetParam = widgetParam;
    EXPECT_EQ(service->CheckSkipLockedBiometricAuth(para, validType), SUCCESS);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(1));
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(1, PIN, COLLECTOR);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    para.widgetParam = widgetParam;
    EXPECT_EQ(service->CheckSkipLockedBiometricAuth(para, validType), SUCCESS);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(1));
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth002, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    AuthParamInner authParam = {};
    WidgetParamInner widgetParam = {};
    std::vector<AuthType> validType;
    authParam.skipLockedBiometricAuth = false;
    int32_t userId = 110;
    ContextFactory::AuthWidgetContextPara para;
    para.userId = userId;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    para.widgetParam = widgetParam;
    EXPECT_EQ(service->CheckSkipLockedBiometricAuth(para, validType), TYPE_NOT_SUPPORT);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth003, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    AuthParamInner authParam = {};
    WidgetParamInner widgetParam = {};
    std::vector<AuthType> validType;
    validType.emplace_back(PIN);
    authParam.skipLockedBiometricAuth = true;
    int32_t userId = 110;
    ContextFactory::AuthWidgetContextPara para;
    para.userId = userId;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillRepeatedly(Return(HDF_SUCCESS));
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(1, PIN, COLLECTOR);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    EXPECT_EQ(service->CheckSkipLockedBiometricAuth(para, authParam, widgetParam, validType), SUCCESS);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(1));
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth004, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    AuthParamInner authParam = {};
    WidgetParamInner widgetParam = {};
    std::vector<AuthType> validType;
    validType.emplace_back(FACE);
    authParam.skipLockedBiometricAuth = true;
    widgetParam.navigationButtonText = "cancel";
    int32_t userId = 110;
    ContextFactory::AuthWidgetContextPara para;
    para.userId = userId;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    para.widgetParam = widgetParam;
    EXPECT_EQ(service->CheckSkipLockedBiometricAuth(para, validType), CANCELED_FROM_WIDGET);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth005, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    AuthParamInner authParam = {};
    WidgetParamInner widgetParam = {};
    std::vector<AuthType> validType;
    validType.emplace_back(FACE);
    authParam.skipLockedBiometricAuth = true;
    widgetParam.navigationButtonText = "";
    int32_t userId = 110;
    ContextFactory::AuthWidgetContextPara para;
    para.userId = userId;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    para.widgetParam = widgetParam;
    EXPECT_EQ(service->CheckSkipLockedBiometricAuth(para, validType), LOCKED);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth006, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    AuthParamInner authParam = {};
    WidgetParamInner widgetParam = {};
    std::vector<AuthType> validType;
    validType.emplace_back(PIN);
    authParam.skipLockedBiometricAuth = true;
    int32_t userId = 110;
    ContextFactory::AuthWidgetContextPara para;
    para.userId = userId;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillRepeatedly(Return(HDF_FAILURE));
    EXPECT_EQ(service->CheckSkipLockedBiometricAuth(para, authParam, widgetParam, validType), LOCKED);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth007, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    AuthParamInner authParam = {};
    WidgetParamInner widgetParam = {};
    std::vector<AuthType> validType;
    validType.emplace_back(FACE);
    authParam.skipLockedBiometricAuth = true;
    int32_t userId = 110;
    ContextFactory::AuthWidgetContextPara para;
    para.userId = userId;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillRepeatedly(Return(HDF_SUCCESS));
    auto resourceNode = Common::MakeShared<MockResourceNode>();
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_CALL(*resourceNode, GetExecutorIndex()).WillRepeatedly(Return(1));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    ON_CALL(*node, GetProperty(_, _))
        .WillByDefault(
            [](const Attributes &condition, Attributes &values) {
                values.SetInt32Value(Attributes::ATTR_CAMERA_STATUS,
                    static_cast<int32_t>(CameraStatus::CAMERA_AVAILABLE));
                values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 0);
                values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 0);
                return SUCCESS;
            }
        );
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    EXPECT_EQ(service->CheckSkipLockedBiometricAuth(para, authParam, widgetParam, validType), LOCKED);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(1));
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth008, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    AuthParamInner authParam = {};
    WidgetParamInner widgetParam = {};
    std::vector<AuthType> validType;
    validType.emplace_back(FACE);
    authParam.skipLockedBiometricAuth = true;
    int32_t userId = 110;
    ContextFactory::AuthWidgetContextPara para;
    para.userId = userId;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _))
        .WillRepeatedly(
            [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
                HdiCredentialInfo tempInfo = {
                    .credentialId = 1,
                    .executorIndex = 1,
                    .templateId = 3,
                    .authType = static_cast<HdiAuthType>(2),
                    .executorMatcher = 2,
                    .executorSensorHint = 3,
                };
                infos.push_back(tempInfo);
                return HDF_SUCCESS;
            }
        );
    auto resourceNode = Common::MakeShared<MockResourceNode>();
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_CALL(*resourceNode, GetExecutorIndex()).WillRepeatedly(Return(1));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    ON_CALL(*node, GetProperty(_, _))
        .WillByDefault(
            [](const Attributes &condition, Attributes &values) {
                values.SetInt32Value(Attributes::ATTR_CAMERA_STATUS,
                    static_cast<int32_t>(CameraStatus::CAMERA_AVAILABLE));
                values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 5);
                values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 0);
                return SUCCESS;
            }
        );
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    para.widgetParam = widgetParam;
    EXPECT_EQ(service->CheckSkipLockedBiometricAuth(para, validType), SUCCESS);
    EXPECT_EQ(validType.size(), 1);
    EXPECT_EQ(validType[0], FACE);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(1));
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth009, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    AuthParamInner authParam = {};
    WidgetParamInner widgetParam = {};
    std::vector<AuthType> validType;
    validType.emplace_back(PIN);
    validType.emplace_back(FACE);
    authParam.skipLockedBiometricAuth = true;
    int32_t userId = 110;
    ContextFactory::AuthWidgetContextPara para;
    para.userId = userId;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillRepeatedly(Return(HDF_SUCCESS));
    auto pinNode = Common::MakeShared<MockResourceNode>();
    EXPECT_NE(pinNode, nullptr);
    EXPECT_CALL(*pinNode, GetExecutorIndex()).WillRepeatedly(Return(1));
    MockResourceNode *pinResourceNode = static_cast<MockResourceNode *>(pinNode.get());
    ON_CALL(*pinResourceNode, GetProperty(_, _))
        .WillByDefault(
            [](const Attributes &condition, Attributes &values) {
                values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, 10001);
                values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 5);
                values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 0);
                return SUCCESS;
            }
        );
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(pinNode));
    auto faceNode = Common::MakeShared<MockResourceNode>();
    EXPECT_NE(faceNode, nullptr);
    EXPECT_CALL(*faceNode, GetExecutorIndex()).WillRepeatedly(Return(2));
    MockResourceNode *faceResourceNode = static_cast<MockResourceNode *>(faceNode.get());
    ON_CALL(*faceResourceNode, GetProperty(_, _))
        .WillByDefault(
            [](const Attributes &condition, Attributes &values) {
                values.SetInt32Value(Attributes::ATTR_CAMERA_STATUS,
                    static_cast<int32_t>(CameraStatus::CAMERA_AVAILABLE));
                values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 0);
                values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 0);
                return SUCCESS;
            }
        );
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(faceNode));
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    para.widgetParam = widgetParam;
    EXPECT_EQ(service->CheckSkipLockedBiometricAuth(para, validType), SUCCESS);
    EXPECT_EQ(validType.size(), 1);
    EXPECT_EQ(validType[0], PIN);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(1));
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(2));
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth010, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    AuthParamInner authParam = {};
    WidgetParamInner widgetParam = {};
    std::vector<AuthType> validType;
    validType.emplace_back(PRIVATE_PIN);
    authParam.skipLockedBiometricAuth = true;
    int32_t userId = 110;
    ContextFactory::AuthWidgetContextPara para;
    para.userId = userId;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillRepeatedly(Return(HDF_SUCCESS));
    auto resourceNode = Common::MakeShared<MockResourceNode>();
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_CALL(*resourceNode, GetExecutorIndex()).WillRepeatedly(Return(1));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    ON_CALL(*node, GetProperty(_, _))
        .WillByDefault(
            [](const Attributes &condition, Attributes &values) {
                values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, 10001);
                values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 0);
                values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 0);
                return SUCCESS;
            }
        );
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    para.widgetParam = widgetParam;
    EXPECT_EQ(service->CheckSkipLockedBiometricAuth(para, validType), SUCCESS);
    EXPECT_EQ(validType.size(), 1);
    EXPECT_EQ(validType[0], PRIVATE_PIN);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(1));
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth011, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    AuthParamInner authParam = {};
    WidgetParamInner widgetParam = {};
    std::vector<AuthType> validType;
    authParam.skipLockedBiometricAuth = true;
    int32_t userId = 110;
    ContextFactory::AuthWidgetContextPara para;
    para.userId = userId;
    para.credentialIdList = authParam.credentialIdList;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    para.widgetParam = widgetParam;
    EXPECT_EQ(service->CheckSkipLockedBiometricAuth(para, validType), TYPE_NOT_SUPPORT);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceFilterFaceNotAvailable001, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    ContextFactory::AuthWidgetContextPara para;
    std::vector<AuthType> validType;
    validType.emplace_back(PIN);
    service->FilterFaceNotAvailable(para, validType);
    EXPECT_EQ(validType.size(), 1);
    EXPECT_EQ(validType[0], PIN);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceFilterFaceNotAvailable002, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    ContextFactory::AuthWidgetContextPara para;
    std::vector<AuthType> validType;
    validType.emplace_back(FACE);
    validType.emplace_back(PIN);
    ContextFactory::AuthProfile profile = {};
    profile.cameraStatus = CameraStatus::CAMERA_AVAILABLE;
    para.authProfileMap[AuthType::FACE] = profile;
    service->FilterFaceNotAvailable(para, validType);
    EXPECT_EQ(validType.size(), 2);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceFilterFaceNotAvailable003, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    ContextFactory::AuthWidgetContextPara para;
    std::vector<AuthType> validType;
    validType.emplace_back(FACE);
    validType.emplace_back(PIN);
    ContextFactory::AuthProfile profile = {};
    profile.cameraStatus = CameraStatus::CAMERA_NOT_AVAILABLE;
    para.authProfileMap[AuthType::FACE] = profile;
    service->FilterFaceNotAvailable(para, validType);
    EXPECT_EQ(validType.size(), 1);
    EXPECT_EQ(validType[0], PIN);
    EXPECT_EQ(para.authProfileMap.find(AuthType::FACE), para.authProfileMap.end());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillRepeatedly(Return(GENERAL_ERROR));
    EXPECT_EQ(service->CheckSkipLockedBiometricAuth(para, validType), LOCKED);
    MockUserAuthEngine::Holder::GetInstance().Reset();
}
