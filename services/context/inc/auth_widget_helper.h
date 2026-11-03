/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef IAM_AUTH_WIDGET_HELPER_H
#define IAM_AUTH_WIDGET_HELPER_H

#include "context_factory.h"
#include "user_auth_common_defines.h"
#include "user_auth_engine_types.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class AuthWidgetHelper {
public:
    static bool InitWidgetContextParam(const AuthParamInner &authParam, std::vector<AuthType> &validType,
        const WidgetParamInner &widgetParam, ContextFactory::AuthWidgetContextPara &para);
    static int32_t CheckValidSolution(int32_t userId,
        const std::vector<AuthType> &authTypeList, const AuthTrustLevel &atl, std::vector<AuthType> &validTypeList);
    static int32_t CheckReuseUnlockResult(const ContextFactory::AuthWidgetContextPara &para,
        const AuthParamInner &authParam, Attributes &extraInfo);
    static int32_t GetUserAuthProfile(int32_t userId, const AuthType &authType,
        ContextFactory::AuthProfile &profile, std::vector<uint64_t> credentialIdList);
    static int32_t QueryReusableAuthResult(const int32_t userId, const AuthParamInner &authParam,
        EngReuseUnlockInfo &reuseResultInfo);

#ifndef IAM_TEST_ENABLE
private:
#endif
    static bool ParseAttributes(const Attributes &values, const AuthType &authType,
        ContextFactory::AuthProfile &profile);
    static int32_t SetReuseUnlockResult(int32_t apiVersion, const EngReuseUnlockInfo &info,
        Attributes &extraInfo);
    static bool GetAuthCredentialList(int32_t userId, const AuthType &authType,
        const std::vector<uint64_t> &credentialIdList,
        std::vector<std::shared_ptr<CredentialInfoInterface>> &credentialInfos);
    static std::vector<uint32_t> GetUint32PropertyKeys(const AuthType &authType);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_AUTH_WIDGET_HELPER_H