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

#ifndef REMOTE_MSG_UTIL_H
#define REMOTE_MSG_UTIL_H

#include "attributes.h"
#include "co_auth_client_defines.h"
#include "iam_logger.h"
#include "user_auth_common_defines.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
enum MessageType {
    // collector remoteAuthService -> verifier remoteAuthService
    START_REMOTE_AUTH = 1,

    // verifier remoteAuthService callback -> collector remoteAuthInvokerContext
    SEND_REMOTE_AUTH_TIP = 2,
    SEND_REMOTE_AUTH_RESULT = 3,

    // verifier remoteAuthInvokerContext -> collector remoteAuthService
    QUERY_EXECUTOR_INFO = 4,

    // verifier executor proxy -> collector remoteAuthService
    BEGIN_EXECUTE = 5,
    END_EXECUTE = 6,

    // verifier executor proxy -> executor stub
    SEND_DATA_TO_EXECUTOR = 7,

    // collector executor stub -> verifier executor proxy
    EXECUTOR_FINISH = 8,
    EXECUTOR_SEND_DATA = 9,
};

class RemoteMsgUtil {
public:
    static bool GetConnectionName(uint64_t contextId, std::string &connectionName);
    static std::string GetExecutorProxyEndPointName();
    static std::string GetExecutorStubEndPointName();
    static std::string GetRemoteServiceEndPointName();
    static std::string GetRemoteCallbackEndPointName();
    static std::string GetRemoteAuthContextEndPointName();
    static std::string GetRemoteAuthInvokerContextEndPointName();

    // QUERY_EXECUTOR_INFO
    static bool GetQueryExecutorInfoReply(const std::vector<int32_t> authTypes, int32_t executorRole,
        std::string remoteUdid, Attributes &attr);
    static bool DecodeQueryExecutorInfoReply(const Attributes &attr, std::vector<ExecutorInfo> &executorInfoArray);

    static bool EncodeAuthParam(const AuthParamInner &authParam, Attributes &attr);
    static bool DecodeAuthParam(const Attributes &attr, AuthParamInner &authParam);

private:
    // QUERY_EXECUTOR_INFO
    static bool EncodeQueryExecutorInfoReply(const std::vector<ExecutorInfo> &executorInfoArray,
        const std::vector<uint8_t> &signedRemoteExecutorInfo, Attributes &attr);
    static bool SetExecutorInfoToAttributes(const ExecutorInfo &executorInfo, Attributes &attr);
    static bool GetExecutorInfoFromAttributes(const Attributes &Attr, std::vector<uint8_t> &signedRemoteExecutorInfo,
        ExecutorInfo &executorInfo);
    static bool SetExecutorInfoArrayToAttributes(const std::vector<ExecutorInfo> &executorInfoArray, Attributes &attr);
    static bool GetExecutorInfoArrayFromAttributes(const Attributes &Attr,
        std::vector<uint8_t> &signedRemoteExecutorInfo, std::vector<ExecutorInfo> &executorInfoArray);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // REMOTE_MSG_UTIL_H