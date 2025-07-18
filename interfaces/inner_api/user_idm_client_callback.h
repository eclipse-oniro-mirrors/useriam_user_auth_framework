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
 * @file user_idm_client_callback.h
 *
 * @brief Callback definitions returned by idm client.
 * @since 3.1
 * @version 3.2
 */

#ifndef USER_IDM_CLIENT_CALLBACK_H
#define USER_IDM_CLIENT_CALLBACK_H

#include "attributes.h"
#include "iam_common_defines.h"
#include "user_idm_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class GetCredentialInfoCallback {
public:
    /**
     * @brief The callback return get credential info result.
     *
     * @param result The result success or error code{@link ResultCode}.
     * @param infoList The credential info list.
     */
    virtual void OnCredentialInfo(int32_t result, const std::vector<CredentialInfo> &infoList) = 0;
};

class GetSecUserInfoCallback {
public:
    /**
     * @brief The callback return get security user info result.
     *
     * @param result The result success or error code{@link ResultCode}.
     * @param info The security user info.
     */
    virtual void OnSecUserInfo(int32_t result, const SecUserInfo &info) = 0;
};

class UserIdmClientCallback {
public:
    /**
     * @brief The callback return authenticate acquire information.
     *
     * @param module Module of current acquire info.
     * @param acquireInfo Acquire info needed to be pass in.
     * @param extraInfo Other related information about authentication.
     */
    virtual void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) = 0;

    /**
     * @brief The callback return set property result.
     *
     * @param result The result success or error code{@link ResultCode}.
     * @param extraInfo Other related information about set property.
     */
    virtual void OnResult(int32_t result, const Attributes &extraInfo) = 0;
};

class CredChangeEventListener {
public:
    /**
     * @brief Notify the event of cred change.
     *
     * @param userId The id of user who change cred.
     * @param authType The authentication auth type{@link AuthType}.
     * @param eventType eventType of cred change, such as addCred and updateCred.
     * @param changeInfo The credential change info.
     */
    virtual void OnNotifyCredChangeEvent(int32_t userId, AuthType authType, CredChangeEventType eventType,
        const CredChangeEventInfo &changeInfo) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // USER_IDM_CLIENT_CALLBACK_H