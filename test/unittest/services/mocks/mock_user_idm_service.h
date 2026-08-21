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
#ifndef IAM_MOCK_USER_IDM_SERVICE_H
#define IAM_MOCK_USER_IDM_SERVICE_H
#include <memory>

#include <gmock/gmock.h>

#include "user_idm_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockUserIdmService final : public UserIdmStub {
public:
    MOCK_METHOD2(OpenSession, int32_t(int32_t userId, std::vector<uint8_t> &challenge));
    MOCK_METHOD1(CloseSession, int32_t(int32_t userId));
    MOCK_METHOD4(GetCredentialInfo, int32_t(int32_t userId, int32_t authType,
        const sptr<IIdmGetCredInfoCallback> &idmGetCredInfoCallback, int32_t &funcResult));
    MOCK_METHOD2(GetSecInfo, int32_t(int32_t userId,
        const sptr<IIdmGetSecureUserInfoCallback> &idmGetSecureUserInfoCallback));
    MOCK_METHOD4(AddCredential, int32_t(int32_t userId, const IpcCredentialPara &ipcCredentialPara,
        const sptr<IIamCallback> &IdmCallback, bool isUpdate));
    MOCK_METHOD3(UpdateCredential, int32_t(int32_t userId, const IpcCredentialPara &ipcCredentialPara,
        const sptr<IIamCallback> &IdmCallback));
    MOCK_METHOD1(Cancel, int32_t(int32_t userId));
    MOCK_METHOD2(EnforceDelUser, int32_t(int32_t userId, const sptr<IIamCallback> &IdmCallback));
    MOCK_METHOD3(DelUser, int32_t(int32_t userId, const std::vector<uint8_t> &authToken,
        const sptr<IIamCallback> &IdmCallback));
    MOCK_METHOD4(DelCredential, int32_t(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
        const sptr<IIamCallback> &IdmCallback));
    MOCK_METHOD1(ClearRedundancyCredential, int32_t(const sptr<IIamCallback> &IdmCallback));
    MOCK_METHOD1(RegistCredChangeEventListener, int32_t(const sptr<IEventListenerCallback> &callback));
    MOCK_METHOD1(UnRegistCredChangeEventListener, int32_t(const sptr<IEventListenerCallback> &callback));
    MOCK_METHOD3(GetCredentialInfoSync, int32_t(int32_t userId, int32_t authType,
        std::vector<IpcCredentialInfo> &ipcCredentialInfoList));
    MOCK_METHOD2(DeleteSubProfile, int32_t(int32_t subProfileId, const sptr<IIamCallback> &idmCallback));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_USER_IDM_SERVICE_H