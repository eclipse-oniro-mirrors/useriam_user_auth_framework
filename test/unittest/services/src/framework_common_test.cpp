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

#include "attributes.h"
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
    // DEVICE_CAPABILITY_NOT_SUPPORT falls through the generic offset formula, lands out of the
    // V10 range and clamps to GENERAL_ERROR; bindings special-case it before calling in.
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(DEVICE_CAPABILITY_NOT_SUPPORT),
        static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR));
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

    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(AUTH_TOKEN_NOT_IN_WINDOW),
        static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR));
    EXPECT_EQ(UserAuthHelper::GetResultCodeV10(AUTH_TOKEN_CREDENTIAL_INVALID),
        static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR));
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperGetResultCodeV16_001, TestSize.Level0)
{
    EXPECT_EQ(UserAuthHelper::GetResultCodeV16(SUCCESS), UserAuthResultCode::SUCCESS);
    EXPECT_EQ(UserAuthHelper::GetResultCodeV16(FAIL), UserAuthResultCode::FAIL);
    EXPECT_EQ(UserAuthHelper::GetResultCodeV16(AUTH_TOKEN_CHECK_FAILED),
        UserAuthResultCode::AUTH_TOKEN_CHECK_FAILED);
    EXPECT_EQ(UserAuthHelper::GetResultCodeV16(AUTH_TOKEN_EXPIRED), UserAuthResultCode::AUTH_TOKEN_EXPIRED);
    EXPECT_EQ(UserAuthHelper::GetResultCodeV16(INVALID_PARAMETERS), UserAuthResultCode::OHOS_INVALID_PARAM);
    EXPECT_EQ(UserAuthHelper::GetResultCodeV16(CHECK_PERMISSION_FAILED),
        UserAuthResultCode::OHOS_CHECK_PERMISSION_FAILED);
    EXPECT_EQ(UserAuthHelper::GetResultCodeV16(CHECK_SYSTEM_APP_FAILED),
        UserAuthResultCode::OHOS_CHECK_SYSTEM_APP_FAILED);
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperGetResultCodeV16_002, TestSize.Level0)
{
    EXPECT_EQ(UserAuthHelper::GetResultCodeV16(AUTH_TOKEN_NOT_IN_WINDOW), UserAuthResultCode::GENERAL_ERROR);
    EXPECT_EQ(UserAuthHelper::GetResultCodeV16(AUTH_TOKEN_CREDENTIAL_INVALID), UserAuthResultCode::GENERAL_ERROR);
    EXPECT_EQ(UserAuthHelper::GetResultCodeV16(9999), UserAuthResultCode::GENERAL_ERROR);
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperGetResultCodeV26_001, TestSize.Level0)
{
    EXPECT_EQ(UserAuthHelper::GetResultCodeV26(AUTH_TOKEN_NOT_IN_WINDOW),
        UserAuthResultCode::AUTH_TOKEN_NOT_IN_WINDOW);
    EXPECT_EQ(UserAuthHelper::GetResultCodeV26(AUTH_TOKEN_CREDENTIAL_INVALID),
        UserAuthResultCode::AUTH_TOKEN_CREDENTIAL_INVALID);
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperGetResultCodeV26_002, TestSize.Level0)
{
    EXPECT_EQ(UserAuthHelper::GetResultCodeV26(SUCCESS), UserAuthResultCode::SUCCESS);
    EXPECT_EQ(UserAuthHelper::GetResultCodeV26(FAIL), UserAuthResultCode::FAIL);
    EXPECT_EQ(UserAuthHelper::GetResultCodeV26(AUTH_TOKEN_CHECK_FAILED),
        UserAuthResultCode::AUTH_TOKEN_CHECK_FAILED);
    EXPECT_EQ(UserAuthHelper::GetResultCodeV26(AUTH_TOKEN_EXPIRED), UserAuthResultCode::AUTH_TOKEN_EXPIRED);
    EXPECT_EQ(UserAuthHelper::GetResultCodeV26(INVALID_PARAMETERS), UserAuthResultCode::OHOS_INVALID_PARAM);
    EXPECT_EQ(UserAuthHelper::GetResultCodeV26(CHECK_PERMISSION_FAILED),
        UserAuthResultCode::OHOS_CHECK_PERMISSION_FAILED);
    EXPECT_EQ(UserAuthHelper::GetResultCodeV26(9999), UserAuthResultCode::GENERAL_ERROR);
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
    EXPECT_TRUE(UserAuthHelper::CheckUserAuthType(static_cast<int32_t>(AuthType::RECOVERY_KEY)));
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

HWTEST_F(FrameworkCommonTest, UserAuthHelperCheckTokenSchedule_001, TestSize.Level0)
{
    EXPECT_EQ(UserAuthHelper::CheckTokenSchedule(std::nullopt), SUCCESS);

    TokenSchedule singleWindow;
    singleWindow.hasValidStartTime = true;
    singleWindow.validStartTime = 1000;
    singleWindow.hasValidEndTime = true;
    singleWindow.validEndTime = 2000;
    EXPECT_EQ(UserAuthHelper::CheckTokenSchedule(singleWindow), SUCCESS);

    TokenSchedule windowed = singleWindow;
    RedemptionWindow window;
    window.repeatInterval = MIN_REPEAT_INTERVAL_MS;
    window.windowDuration = MIN_REPEAT_INTERVAL_MS;
    windowed.windowConfig = window;
    EXPECT_EQ(UserAuthHelper::CheckTokenSchedule(windowed), SUCCESS);

    window.windowDuration = 300;
    windowed.windowConfig = window;
    EXPECT_EQ(UserAuthHelper::CheckTokenSchedule(windowed), SUCCESS);

    // optional start/end: unset start means from issuance, unset end means no limit
    TokenSchedule openEnded;
    openEnded.hasValidEndTime = true;
    openEnded.validEndTime = 2000;
    EXPECT_EQ(UserAuthHelper::CheckTokenSchedule(openEnded), SUCCESS);
    openEnded.hasValidEndTime = false;
    openEnded.hasValidStartTime = true;
    openEnded.validStartTime = 1000;
    EXPECT_EQ(UserAuthHelper::CheckTokenSchedule(openEnded), SUCCESS);
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperCheckTokenSchedule_002, TestSize.Level0)
{
    TokenSchedule schedule;
    schedule.hasValidStartTime = true;
    schedule.validStartTime = 2000;
    schedule.hasValidEndTime = true;
    schedule.validEndTime = 2000;
    EXPECT_EQ(UserAuthHelper::CheckTokenSchedule(schedule), INVALID_PARAMETERS);

    schedule.validEndTime = 1000;
    EXPECT_EQ(UserAuthHelper::CheckTokenSchedule(schedule), INVALID_PARAMETERS);
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperCheckTokenSchedule_003, TestSize.Level0)
{
    TokenSchedule schedule;
    schedule.hasValidStartTime = true;
    schedule.validStartTime = 0;
    schedule.hasValidEndTime = true;
    schedule.validEndTime = 365LL * 24 * 60 * 60 * 1000;
    EXPECT_EQ(UserAuthHelper::CheckTokenSchedule(schedule), INVALID_PARAMETERS);

    // span equal to the 30-day cap is allowed; unset end has no span limit
    schedule.validEndTime = MAX_TOKEN_SCHEDULE_SPAN_MS;
    EXPECT_EQ(UserAuthHelper::CheckTokenSchedule(schedule), SUCCESS);
    schedule.hasValidEndTime = false;
    EXPECT_EQ(UserAuthHelper::CheckTokenSchedule(schedule), SUCCESS);
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperCheckTokenSchedule_004, TestSize.Level0)
{
    TokenSchedule schedule;
    schedule.hasValidStartTime = true;
    schedule.validStartTime = 1000;
    schedule.hasValidEndTime = true;
    schedule.validEndTime = 2000;
    RedemptionWindow window;
    window.repeatInterval = 0;
    schedule.windowConfig = window;
    EXPECT_EQ(UserAuthHelper::CheckTokenSchedule(schedule), INVALID_PARAMETERS);

    // repeatInterval below 1 hour is rejected
    window.repeatInterval = MIN_REPEAT_INTERVAL_MS - 1;
    window.windowDuration = 0;
    schedule.windowConfig = window;
    EXPECT_EQ(UserAuthHelper::CheckTokenSchedule(schedule), INVALID_PARAMETERS);

    window.repeatInterval = MIN_REPEAT_INTERVAL_MS;
    window.windowDuration = 0;
    schedule.windowConfig = window;
    EXPECT_EQ(UserAuthHelper::CheckTokenSchedule(schedule), INVALID_PARAMETERS);

    window.windowDuration = MIN_REPEAT_INTERVAL_MS + 1;
    schedule.windowConfig = window;
    EXPECT_EQ(UserAuthHelper::CheckTokenSchedule(schedule), INVALID_PARAMETERS);

    window.windowDuration = MIN_REPEAT_INTERVAL_MS;
    schedule.windowConfig = window;
    EXPECT_EQ(UserAuthHelper::CheckTokenSchedule(schedule), SUCCESS);
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperCheckAuthTokenParam_001, TestSize.Level0)
{
    EXPECT_FALSE(UserAuthHelper::CheckAuthTokenParam({}));

    std::vector<uint8_t> token(MAX_AUTH_TOKEN_LEN, 1);
    EXPECT_TRUE(UserAuthHelper::CheckAuthTokenParam(token));

    token.resize(MAX_AUTH_TOKEN_LEN + 1);
    EXPECT_FALSE(UserAuthHelper::CheckAuthTokenParam(token));
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperCheckChallengeParam_001, TestSize.Level0)
{
    EXPECT_TRUE(UserAuthHelper::CheckChallengeParam({}));

    std::vector<uint8_t> challenge(MAX_CHALLENG_LEN, 1);
    EXPECT_TRUE(UserAuthHelper::CheckChallengeParam(challenge));

    challenge.resize(MAX_CHALLENG_LEN + 1);
    EXPECT_FALSE(UserAuthHelper::CheckChallengeParam(challenge));
}

HWTEST_F(FrameworkCommonTest, UserAuthHelperTokenScheduleAttr_001, TestSize.Level0)
{
    Attributes extraInfo;
    TokenSchedule schedule;
    schedule.hasValidStartTime = true;
    schedule.validStartTime = 1000;
    schedule.hasValidEndTime = true;
    schedule.validEndTime = 2000;
    RedemptionWindow window;
    window.repeatInterval = 500;
    window.windowDuration = 300;
    schedule.windowConfig = window;
    EXPECT_TRUE(UserAuthHelper::SetTokenScheduleAttr(schedule, extraInfo));

    TokenSchedule decoded = {};
    EXPECT_TRUE(UserAuthHelper::GetTokenScheduleAttr(extraInfo, decoded));
    EXPECT_TRUE(decoded.hasValidStartTime);
    EXPECT_EQ(decoded.validStartTime, 1000);
    EXPECT_TRUE(decoded.hasValidEndTime);
    EXPECT_EQ(decoded.validEndTime, 2000);
    ASSERT_TRUE(decoded.windowConfig.has_value());
    EXPECT_EQ(decoded.windowConfig->repeatInterval, 500);
    EXPECT_EQ(decoded.windowConfig->windowDuration, 300);

    TokenSchedule singleWindow;
    singleWindow.hasValidStartTime = true;
    singleWindow.validStartTime = 1000;
    singleWindow.hasValidEndTime = true;
    singleWindow.validEndTime = 2000;
    Attributes singleInfo;
    EXPECT_TRUE(UserAuthHelper::SetTokenScheduleAttr(singleWindow, singleInfo));
    EXPECT_TRUE(UserAuthHelper::GetTokenScheduleAttr(singleInfo, decoded));
    EXPECT_FALSE(decoded.windowConfig.has_value());

    // optional start/end: only windowConfig is declared, start means issuance and end means no limit
    TokenSchedule windowOnly;
    windowOnly.windowConfig = window;
    Attributes windowOnlyInfo;
    EXPECT_TRUE(UserAuthHelper::SetTokenScheduleAttr(windowOnly, windowOnlyInfo));
    EXPECT_TRUE(UserAuthHelper::GetTokenScheduleAttr(windowOnlyInfo, decoded));
    EXPECT_FALSE(decoded.hasValidStartTime);
    EXPECT_FALSE(decoded.hasValidEndTime);
    ASSERT_TRUE(decoded.windowConfig.has_value());

    Attributes emptyInfo;
    EXPECT_TRUE(UserAuthHelper::SetTokenScheduleAttr(std::nullopt, emptyInfo));
    EXPECT_FALSE(UserAuthHelper::GetTokenScheduleAttr(emptyInfo, decoded));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS