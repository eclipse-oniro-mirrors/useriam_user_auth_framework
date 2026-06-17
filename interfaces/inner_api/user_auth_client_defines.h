/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

/**
 * @file co_auth_client_defines.h
 *
 * @brief Type definitions used by user auth client.
 * @since 3.1
 * @version 3.2
 */

#ifndef USER_AUTH_CLIENT_DEFINES_H
#define USER_AUTH_CLIENT_DEFINES_H

#include <vector>

#include "attributes.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
const uint64_t MAX_ALLOWABLE_REUSE_DURATION = 5 * 60 * 1000;

/**
 * @brief Remote auth parameter.
 */
struct RemoteAuthParam {
    /** verifier network id */
    std::optional<std::string> verifierNetworkId;
    /** collector network id */
    std::optional<std::string> collectorNetworkId;
    /** collector token id */
    std::optional<uint32_t> collectorTokenId;
};

/**
 * @brief Auth parameter.
 */
struct AuthParam {
    /** user id */
    int32_t userId;
    /** challenge value */
    std::vector<uint8_t> challenge;
    /** Credential type for authentication. */
    AuthType authType;
    /** Trust level of authentication result. */
    AuthTrustLevel authTrustLevel;
    /** Auth intention. */
    AuthIntent authIntent;
    /** Remote auth parameter. */
    std::optional<RemoteAuthParam> remoteAuthParam;
    /** Additional info. */
    std::string additionalInfo;
};

/**
 * @brief Window mode type for user authentication widget.
 */
enum WindowModeType : int32_t {
    /** Window mode type is dialog box. */
    DIALOG_BOX = 1,
    /**  Window mode type is full screen. */
    FULLSCREEN = 2,
    /**  Window mode type is not set */
    UNKNOWN_WINDOW_MODE = 3,
    /**  Window mode type is none interruption dialog box. */
    NONE_INTERRUPTION_DIALOG_BOX = 4
};

/**
 * @brief The mode for reusing unlock authentication result.
 */
enum ReuseMode : uint32_t {
    /** Authentication type relevant.The unlock authentication result can be reused only when the result is within
     * valid duration as well as it comes from one of specified UserAuthTypes of the AuthParam. */
    AUTH_TYPE_RELEVANT = 1,
    /** Authentication type irrelevant.The unlock authentication result can be reused as long as the result is within
     * valid duration. */
    AUTH_TYPE_IRRELEVANT = 2,
    /** Caller irrelevant authentication type relevant.The unlock authentication result can be reused only when the
     * result is within valid duration as well as it comes from one of specified UserAuthTypes of the AuthParam. */
    CALLER_IRRELEVANT_AUTH_TYPE_RELEVANT = 3,
    /** Caller irrelevant authentication type irrelevant.The unlock authentication result can be reused as long as the
     * result is within valid duration. */
    CALLER_IRRELEVANT_AUTH_TYPE_IRRELEVANT = 4,
};

/**
 * @brief Reuse unlock authentication result.
 */
struct ReuseUnlockResult {
    /** Whether to reuse unlock result, ReuseUnlockResult is valid only when isReuse is true.*/
    bool isReuse {false};
    /** The mode for reusing unlock authentication result. */
    ReuseMode reuseMode {AUTH_TYPE_IRRELEVANT};
    /** The allowable reuse duration.The value of duration should be between 0 and MAX_ALLOWABLE_REUSE_DURATION. */
    uint64_t reuseDuration {0};
};

/**
 * @brief Auth widget parameter.
 */
struct WidgetParam {
    /** Title of widget. */
    std::string title;
    /** The description text of navigation button. */
    std::string navigationButtonText;
    /** Full screen or not. */
    WindowModeType windowMode;
};

/**
 * @brief Auth widget parameter.
 */
struct WidgetAuthParam {
    /** user id */
    int32_t userId;
    /** challenge value */
    std::vector<uint8_t> challenge;
    /** Credential type for authentication. */
    std::vector<AuthType> authTypes;
    /** Trust level of authentication result. */
    AuthTrustLevel authTrustLevel;
    /** Reuse unlock authentication result. */
    ReuseUnlockResult reuseUnlockResult;
};

/**
 * @brief Executor property needed to get.
 */
struct GetPropertyRequest {
    /** Auth type supported by executor. */
    AuthType authType {0};
    /** The keys of attribute needed to get. */
    std::vector<Attributes::AttributeKey> keys {};
};

/**
 * @brief Executor property needed to set.
 */
struct SetPropertyRequest {
    /** Auth type supported by executor. */
    AuthType authType {0};
    /**  The executor's property mode. */
    PropertyMode mode {0};
    /** The attributes needed to set. */
    Attributes attrs {};
};

/**
 * @brief Global config type.
 */
enum GlobalConfigType : int32_t {
    /** Pin expired period, valid only for pin. */
    PIN_EXPIRED_PERIOD = 1,
    /** Enable specified authType capability. */
    ENABLE_STATUS = 2,
    /** Cryptographic algorithm used for PIN processing. */
    PIN_ALGO_TYPE = 3,
};

/**
 * @brief Pin encryption algorithm type.
 */
enum PinEncrypAlgoType : uint32_t {
    /** AES-GCM algorithm */
    AES_GCM = 0,
    /** SM4 algorithm */
    SM4 = 1,
};

/**
 * @brief Global config value.
 */
union GlobalConfigValue {
    /** Global config value of pin expired period.It's value should between 0 and 2^50.
      * When pinExpiredPeriod <= 0, userAuth won't check pin expired period. */
    int64_t pinExpiredPeriod;
    /** Enable specified authType capability. */
    bool enableStatus;
    /** Specified algorithms used for PIN processing.
     * 0: default Scrypt, AES, HKDF
     * 1: replace AES with SM4, compared to 0;
     * Others: not support yet. */
    uint32_t pinAlgoType;
};

/**
 * @brief Global config param.
 */
struct GlobalConfigParam {
    /** Global config type. */
    GlobalConfigType type;
    /** Global config value. */
    GlobalConfigValue value;
    /** Specified userIds. GlobalConfigParam will be effect for all userspaces when the array is empty. */
    std::vector<int32_t> userIds;
    /** Specified authTypes. Should not empty. */
    std::vector<AuthType> authTypes;
};

/**
 * @brief Auth success event info.
 */
struct AuthSuccessEventInfo {
    /** The callerName who auth success. */
    std::string callerName;
    /** The callerType who auth success. */
    int32_t callerType;
    /** Is widget auth. */
    bool isWidgetAuth {false};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_CLIENT_DEFINES_H