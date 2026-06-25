/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#ifndef IAM_MOCK_USER_AUTH_SERVICE_H
#define IAM_MOCK_USER_AUTH_SERVICE_H

#include <gmock/gmock.h>

#include "modal_callback_stub.h"
#include "user_auth_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockUserAuthService final : public UserAuthStub {
public:
    MOCK_METHOD4(GetEnrolledState, int32_t(int32_t apiVersion, int32_t authType,
        IpcEnrolledState &ipcEnrolledState, int32_t &funcResult));

    MOCK_METHOD5(GetAvailableStatus, int32_t(int32_t apiVersion, int32_t userId, int32_t authType,
        uint32_t authTrustLevel, int32_t &funcResult));

    int32_t GetAvailableStatus(int32_t apiVersion, int32_t authType, uint32_t authTrustLevel, int32_t &funcResult)
    {
        return 0;
    }

    MOCK_METHOD4(GetProperty, int32_t(int32_t userId, int32_t authType, const std::vector<uint32_t> &keys,
        const sptr<IGetExecutorPropertyCallback> &getExecutorPropertyCallback));
    
    MOCK_METHOD3(GetPropertyById, int32_t(uint64_t credentialId, const std::vector<uint32_t> &keys,
        const sptr<IGetExecutorPropertyCallback> &getExecutorPropertyCallback));

    MOCK_METHOD4(SetProperty, int32_t(int32_t userId, int32_t authType, const std::vector<uint8_t> &attributes,
        const sptr<ISetExecutorPropertyCallback> &setExecutorPropertyCallback));

    MOCK_METHOD4(AuthUser, int32_t(const IpcAuthParamInner &ipcAuthParamInner,
        const IpcRemoteAuthParam &ipcRemoteAuthParam, const sptr<IIamCallback> &userAuthCallback,
        uint64_t &contextId));
    
    MOCK_METHOD4(Auth, int32_t(int32_t apiVersion, const IpcAuthParamInner &ipcAuthParamInner,
        const sptr<IIamCallback> &userAuthCallback, uint64_t &contextI));

    MOCK_METHOD6(AuthWidget, int32_t(int32_t apiVersion, const IpcAuthParamInner &ipcAuthParamInner,
        const IpcWidgetParamInner &ipcWidgetParamInner, const sptr<IIamCallback> &userAuthCallback,
        const sptr<IModalCallback> &modalCallback, uint64_t &contextId));

    MOCK_METHOD4(Identify, int32_t(const std::vector<uint8_t> &challenge, int32_t authType,
        const sptr<IIamCallback> &userAuthCallback, uint64_t &contextId));

    MOCK_METHOD2(CancelAuthOrIdentify, int32_t(uint64_t contextId, int32_t cancelReason));
    MOCK_METHOD1(GetVersion, int32_t(int32_t &version));
    MOCK_METHOD2(Notice, int32_t(int32_t noticeType, const std::string &eventData));
    MOCK_METHOD2(RegisterWidgetCallback, int32_t(int32_t version, const sptr<IWidgetCallback> &widgetCallback));
    MOCK_METHOD1(RegistUserAuthSuccessEventListener, int32_t(const sptr<IEventListenerCallback> &listener));
    MOCK_METHOD1(UnRegistUserAuthSuccessEventListener, int32_t(const sptr<IEventListenerCallback> &listener));
    MOCK_METHOD1(SetGlobalConfigParam, int32_t(const IpcGlobalConfigParam &ipcGlobalConfigParam));
    MOCK_METHOD2(PrepareRemoteAuth, int32_t(const std::string &networkId,
        const sptr<IIamCallback> &userAuthCallback));
    MOCK_METHOD3(VerifyAuthToken, int32_t(const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
        const sptr<IVerifyTokenCallback> &verifyTokenCallback));
    MOCK_METHOD2(QueryReusableAuthResult, int32_t(const IpcAuthParamInner &ipcAuthParamInner,
        std::vector<uint8_t> &token));
    MOCK_METHOD2(GetAuthLockState, int32_t(int32_t authType,
        const sptr<IGetExecutorPropertyCallback> &getExecutorPropertyCallback));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
    MOCK_METHOD1(RegisterRemoteAuthCallback, int32_t(const sptr<IRemoteAuthCallback> &remoteAuthCallback));
    MOCK_METHOD0(UnregisterRemoteAuthCallback, int32_t());
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_USER_AUTH_SERVICE_H