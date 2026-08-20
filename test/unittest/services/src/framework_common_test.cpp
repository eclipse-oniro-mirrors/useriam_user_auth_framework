/*
 * Copyright (C) 2022-2025 Huawei Device Co., Ltd.
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

#include <climits>
#include <gtest/gtest.h>

#include "auth_common.h"
#include "iam_common_defines.h"
#include "user_auth_helper.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class FrameworkCommonTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
    }

    static void TearDownTestCase()
    {
    }

    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

HWTEST_F(FrameworkCommonTest, UserAuthHelperGetUtf8CharCount, TestSize.Level0)
{
    EXPECT_EQ(UserAuthHelper::GetUtf8CharCount(""), 0);
    EXPECT_EQ(UserAuthHelper::GetUtf8CharCount("Hello"), 5);
    EXPECT_EQ(UserAuthHelper::GetUtf8CharCount("你好"), 2);
    EXPECT_EQ(UserAuthHelper::GetUtf8CharCount("Hello你好World"), 12);
    EXPECT_EQ(UserAuthHelper::GetUtf8CharCount("😀😁"), 2);
    EXPECT_EQ(UserAuthHelper::GetUtf8CharCount("\xE2\x28\xA1"), 1);
    EXPECT_EQ(UserAuthHelper::GetUtf8CharCount("\xC2\xA0"), 1);
    EXPECT_EQ(UserAuthHelper::GetUtf8CharCount("\x80"), 1);
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperGetResultCodeV10_001, TestSize.Level0)
{
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(CHECK_PERMISSION_FAILED),
        static_cast<int32_t>(UserAuthResultCode::OHOS_CHECK_PERMISSION_FAILED));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(INVALID_PARAMETERS),
        static_cast<int32_t>(UserAuthResultCode::OHOS_INVALID_PARAM));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(CHECK_SYSTEM_APP_FAILED),
        static_cast<int32_t>(UserAuthResultCode::OHOS_CHECK_SYSTEM_APP_FAILED));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(HARDWARE_NOT_SUPPORTED),
        static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(DEVICE_CAPABILITY_NOT_SUPPORT),
        static_cast<int32_t>(UserAuthResultCode::OHOS_CAPABILITY_NOT_SUPPORTED));
}

// ENGINE_UNAVAILABLE (e.g. auth engine not loaded) must map to GENERAL_ERROR.
HWTEST_F(FrameworkCommonTest, UserAuthHelperGetResultCodeV10EngineUnavailable, TestSize.Level0)
{
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(ENGINE_UNAVAILABLE),
        static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR));
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperGetResultCodeV10_002, TestSize.Level0)
{
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(SUCCESS),
        static_cast<int32_t>(UserAuthResultCode::SUCCESS));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(FAIL),
        static_cast<int32_t>(UserAuthResultCode::FAIL));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(GENERAL_ERROR),
        static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(CANCELED),
        static_cast<int32_t>(UserAuthResultCode::CANCELED));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(TIMEOUT),
        static_cast<int32_t>(UserAuthResultCode::TIMEOUT));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(TYPE_NOT_SUPPORT),
        static_cast<int32_t>(UserAuthResultCode::TYPE_NOT_SUPPORT));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(TRUST_LEVEL_NOT_SUPPORT),
        static_cast<int32_t>(UserAuthResultCode::TRUST_LEVEL_NOT_SUPPORT));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(LOCKED),
        static_cast<int32_t>(UserAuthResultCode::LOCKED));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(NOT_ENROLLED),
        static_cast<int32_t>(UserAuthResultCode::NOT_ENROLLED));
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperGetResultCodeV10_003, TestSize.Level0)
{
    int32_t overflowResult = INT32_MAX - static_cast<int32_t>(UserAuthResultCode::RESULT_CODE_V10_MIN) + 1;
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(overflowResult),
        static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR));
    
    int32_t outOfRangeResult = 100;
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(outOfRangeResult),
        static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR));
    
    int32_t negativeResult = -1;
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(negativeResult),
        static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR));
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperGetResultCodeV20_001, TestSize.Level0)
{
    EXPECT_EQ(UserAuthHelper::GetResultCodeV20(INVALID_PARAMETERS),
        static_cast<int32_t>(UserAuthResultCode::PARAM_VERIFIED_FAILED));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV20(REUSE_AUTH_RESULT_FAILED),
        static_cast<int32_t>(UserAuthResultCode::REUSE_AUTH_RESULT_FAILED));
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperGetResultCodeV20_002, TestSize.Level0)
{
    EXPECT_EQ(UserAuthHelper::GetResultCodeV20(SUCCESS),
        static_cast<int32_t>(UserAuthResultCode::SUCCESS));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV20(FAIL),
        static_cast<int32_t>(UserAuthResultCode::FAIL));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV20(CHECK_PERMISSION_FAILED),
        static_cast<int32_t>(UserAuthResultCode::OHOS_CHECK_PERMISSION_FAILED));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV20(CHECK_SYSTEM_APP_FAILED),
        static_cast<int32_t>(UserAuthResultCode::OHOS_CHECK_SYSTEM_APP_FAILED));
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperGetResultCodeV21_001, TestSize.Level0)
{
    EXPECT_EQ(UserAuthHelper::GetResultCodeV21(TYPE_NOT_SUPPORT),
        static_cast<int32_t>(UserAuthResultCode::TYPE_NOT_SUPPORT));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV21(NOT_ENROLLED),
        static_cast<int32_t>(UserAuthResultCode::NOT_ENROLLED));
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperGetResultCodeV21_002, TestSize.Level0)
{
    EXPECT_EQ(UserAuthHelper::GetResultCodeV21(SUCCESS),
        static_cast<int32_t>(UserAuthResultCode::SUCCESS));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV21(FAIL),
        static_cast<int32_t>(UserAuthResultCode::FAIL));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV21(INVALID_PARAMETERS),
        static_cast<int32_t>(UserAuthResultCode::PARAM_VERIFIED_FAILED));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV21(REUSE_AUTH_RESULT_FAILED),
        static_cast<int32_t>(UserAuthResultCode::REUSE_AUTH_RESULT_FAILED));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV21(CHECK_PERMISSION_FAILED),
        static_cast<int32_t>(UserAuthResultCode::OHOS_CHECK_PERMISSION_FAILED));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV21(CHECK_SYSTEM_APP_FAILED),
        static_cast<int32_t>(UserAuthResultCode::OHOS_CHECK_SYSTEM_APP_FAILED));
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperCheckUserAuthType_001, TestSize.Level0)
{
    EXPECT_TRUE(UserAuthHelper::CheckUserAuthType(static_cast<int32_t>(AuthType::PIN)));
    EXPECT_TRUE(UserAuthHelper::CheckUserAuthType(static_cast<int32_t>(AuthType::FACE)));
    EXPECT_TRUE(UserAuthHelper::CheckUserAuthType(static_cast<int32_t>(AuthType::FINGERPRINT)));
    EXPECT_TRUE(UserAuthHelper::CheckUserAuthType(static_cast<int32_t>(AuthType::PRIVATE_PIN)));
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperCheckUserAuthType_002, TestSize.Level0)
{
    EXPECT_FALSE(UserAuthHelper::CheckUserAuthType(static_cast<int32_t>(AuthType::ALL)));
    EXPECT_FALSE(UserAuthHelper::CheckUserAuthType(static_cast<int32_t>(AuthType::RECOVERY_KEY)));
    EXPECT_FALSE(UserAuthHelper::CheckUserAuthType(static_cast<int32_t>(AuthType::TUI_PIN)));
    EXPECT_TRUE(UserAuthHelper::CheckUserAuthType(static_cast<int32_t>(AuthType::COMPANION_DEVICE)));
    EXPECT_FALSE(UserAuthHelper::CheckUserAuthType(static_cast<int32_t>(AuthType::INVALID_AUTH_TYPE)));
    EXPECT_FALSE(UserAuthHelper::CheckUserAuthType(999));
    EXPECT_FALSE(UserAuthHelper::CheckUserAuthType(-1));
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperCheckAuthTrustLevel_001, TestSize.Level0)
{
    EXPECT_TRUE(UserAuthHelper::CheckAuthTrustLevel(static_cast<uint32_t>(AuthTrustLevel::ATL1)));
    EXPECT_TRUE(UserAuthHelper::CheckAuthTrustLevel(static_cast<uint32_t>(AuthTrustLevel::ATL2)));
    EXPECT_TRUE(UserAuthHelper::CheckAuthTrustLevel(static_cast<uint32_t>(AuthTrustLevel::ATL3)));
    EXPECT_TRUE(UserAuthHelper::CheckAuthTrustLevel(static_cast<uint32_t>(AuthTrustLevel::ATL4)));
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperCheckAuthTrustLevel_002, TestSize.Level0)
{
    EXPECT_FALSE(UserAuthHelper::CheckAuthTrustLevel(0));
    EXPECT_FALSE(UserAuthHelper::CheckAuthTrustLevel(5000));
    EXPECT_FALSE(UserAuthHelper::CheckAuthTrustLevel(15000));
    EXPECT_FALSE(UserAuthHelper::CheckAuthTrustLevel(50000));
    EXPECT_FALSE(UserAuthHelper::CheckAuthTrustLevel(UINT32_MAX));
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperCheckReuseUnlockResult_001, TestSize.Level0)
{
    ReuseUnlockResult validResult;
    validResult.reuseMode = ReuseMode::AUTH_TYPE_RELEVANT;
    validResult.reuseDuration = 60 * 1000;
    EXPECT_TRUE(UserAuthHelper::CheckReuseUnlockResult(validResult));
    
    validResult.reuseMode = ReuseMode::AUTH_TYPE_IRRELEVANT;
    EXPECT_TRUE(UserAuthHelper::CheckReuseUnlockResult(validResult));
    
    validResult.reuseMode = ReuseMode::CALLER_IRRELEVANT_AUTH_TYPE_RELEVANT;
    EXPECT_TRUE(UserAuthHelper::CheckReuseUnlockResult(validResult));
    
    validResult.reuseMode = ReuseMode::CALLER_IRRELEVANT_AUTH_TYPE_IRRELEVANT;
    EXPECT_TRUE(UserAuthHelper::CheckReuseUnlockResult(validResult));
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperCheckReuseUnlockResult_002, TestSize.Level0)
{
    ReuseUnlockResult invalidResult;
    invalidResult.reuseDuration = 60 * 1000;
    
    invalidResult.reuseMode = static_cast<ReuseMode>(0);
    EXPECT_FALSE(UserAuthHelper::CheckReuseUnlockResult(invalidResult));
    
    invalidResult.reuseMode = static_cast<ReuseMode>(5);
    EXPECT_FALSE(UserAuthHelper::CheckReuseUnlockResult(invalidResult));
    
    invalidResult.reuseMode = static_cast<ReuseMode>(100);
    EXPECT_FALSE(UserAuthHelper::CheckReuseUnlockResult(invalidResult));
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperCheckReuseUnlockResult_003, TestSize.Level0)
{
    ReuseUnlockResult invalidResult;
    invalidResult.reuseMode = ReuseMode::AUTH_TYPE_RELEVANT;
    
    invalidResult.reuseDuration = 0;
    EXPECT_FALSE(UserAuthHelper::CheckReuseUnlockResult(invalidResult));
    
    invalidResult.reuseDuration = MAX_ALLOWABLE_REUSE_DURATION + 1;
    EXPECT_FALSE(UserAuthHelper::CheckReuseUnlockResult(invalidResult));
    
    invalidResult.reuseDuration = UINT64_MAX;
    EXPECT_FALSE(UserAuthHelper::CheckReuseUnlockResult(invalidResult));
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperCheckReuseUnlockResult_004, TestSize.Level0)
{
    ReuseUnlockResult validResult;
    validResult.reuseMode = ReuseMode::AUTH_TYPE_RELEVANT;
    
    validResult.reuseDuration = 1;
    EXPECT_TRUE(UserAuthHelper::CheckReuseUnlockResult(validResult));
    
    validResult.reuseDuration = MAX_ALLOWABLE_REUSE_DURATION;
    EXPECT_TRUE(UserAuthHelper::CheckReuseUnlockResult(validResult));
    
    validResult.reuseDuration = 5 * 60 * 1000;
    EXPECT_TRUE(UserAuthHelper::CheckReuseUnlockResult(validResult));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS