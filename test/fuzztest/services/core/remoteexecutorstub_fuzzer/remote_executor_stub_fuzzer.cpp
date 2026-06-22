/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "remote_executor_stub_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "attributes.h"
#include "iam_fuzz_test.h"
#include "iam_common_defines.h"
#include "iam_ptr.h"
#include "iam_logger.h"
#include "remote_executor_stub.h"
#include "user_auth_service.h"
#include "remote_executor_proxy.h"
#include "remote_msg_util.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_REMOTE_EXECUTOR_STUB

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {

auto g_RemoteExecutorStub = MakeShared<RemoteExecutorStub>();

void FillIAttributes(Parcel &parcel, Attributes &attributes)
{
    bool fillNull = parcel.ReadBool();
    if (fillNull) {
        return;
    }

    attributes.SetUint64Value(Attributes::ATTR_TEMPLATE_ID, parcel.ReadUint64());
    attributes.SetUint64Value(Attributes::ATTR_CALLER_UID, parcel.ReadUint64());
    attributes.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, parcel.ReadUint32());
    attributes.SetUint32Value(Attributes::ATTR_MSG_TYPE, parcel.ReadUint32());
    attributes.SetUint32Value(Attributes::ATTR_REMAIN_TIMES, parcel.ReadUint32());
    attributes.SetUint32Value(Attributes::ATTR_FREEZING_TIME, parcel.ReadUint32());
    std::vector<uint64_t> templateIdList;
    FillFuzzUint64Vector(parcel, templateIdList);
    attributes.SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIdList);
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(parcel, extraInfo);
    attributes.SetUint64ArrayValue(Attributes::ATTR_EXTRA_INFO, templateIdList);
    attributes.SetUint64Value(Attributes::ATTR_CALLER_UID, parcel.ReadUint64());
    attributes.SetUint32Value(Attributes::ATTR_SCHEDULE_MODE, parcel.ReadUint32());
    attributes.SetUint64Value(Attributes::ATTR_SCHEDULE_ID, parcel.ReadUint64());
}

void FuzzTest(Parcel &parcel)
{
    IAM_LOGI("begin");
    if (g_RemoteExecutorStub == nullptr) {
        return;
    }
    std::vector<uint8_t> uint8Vector;
    FillFuzzUint8Vector(parcel, uint8Vector);

    Attributes attr = Attributes();
    FillIAttributes(parcel, attr);
    RemoteExecuteTrace trace = {};
    trace.scheduleId = parcel.ReadUint64();
    attr.SetUint64Value(Attributes::ATTR_SCHEDULE_ID, trace.scheduleId);
    std::string connectionName = parcel.ReadString();
    trace.connectionName = connectionName;
    attr.SetStringValue(Attributes::ATTR_CONNECTION_NAME, connectionName);
    trace.operationResult = parcel.ReadInt32();
    g_RemoteExecutorStub->ProcBeginExecuteRequest(attr, trace);

    std::string srcEndPoint = parcel.ReadString();
    auto request = MakeShared<Attributes>();
    if (request == nullptr) {
        return;
    }
    request->SetInt32Value(Attributes::ATTR_MSG_TYPE, parcel.ReadInt32());
    auto reply = MakeShared<Attributes>(uint8Vector);
    g_RemoteExecutorStub->OnMessage(connectionName, srcEndPoint, request, reply);

    ExecutorRole role = static_cast<ExecutorRole>(parcel.ReadInt32());
    g_RemoteExecutorStub->OnMessage(role, uint8Vector);

    ResultCode resultCode = static_cast<ResultCode>(parcel.ReadInt32());
    auto finalResult = MakeShared<Attributes>(uint8Vector);
    g_RemoteExecutorStub->ContinueSchedule(resultCode, finalResult);

    g_RemoteExecutorStub->ProcSendDataMsg(attr);
    IAM_LOGI("end");
}

void RemoteExecutorProxyFuzzTest(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::string connectionName = parcel.ReadString();
    ExecutorInfo regiregisterInfo = {};
    auto remoteExecutorProxy = MakeShared<RemoteExecutorProxy>(connectionName, regiregisterInfo);
    if (remoteExecutorProxy == nullptr) {
        return;
    }
    remoteExecutorProxy->Start();

    std::string srcEndPoint = parcel.ReadString();
    auto request = MakeShared<Attributes>();
    if (request == nullptr) {
        return;
    }
    request->SetUint32Value(Attributes::ATTR_MSG_TYPE, parcel.ReadUint32());
    auto reply = MakeShared<Attributes>();
    remoteExecutorProxy->OnMessage(connectionName, srcEndPoint, request, reply);
    remoteExecutorProxy->OnConnectStatus(connectionName, ConnectStatus::DISCONNECTED);
    shared_ptr<ExecutorMessenger> messenger = nullptr;
    uint64_t scheduleId = parcel.ReadUint64();
    std::vector<uint8_t> publicKey;
    FillFuzzUint8Vector(parcel, publicKey);
    std::vector<uint64_t> templateIdList;
    FillFuzzUint64Vector(parcel, templateIdList);
    remoteExecutorProxy->OnMessengerReady(messenger, publicKey, templateIdList);
    Attributes command;
    FillIAttributes(parcel, command);
    remoteExecutorProxy->OnBeginExecute(scheduleId, publicKey, command);
    remoteExecutorProxy->OnEndExecute(scheduleId, command);
    remoteExecutorProxy->OnSendData(scheduleId, command);
    remoteExecutorProxy->ProcSendDataMsg(command);
    remoteExecutorProxy->OnErrorFinish(scheduleId);

    IAM_LOGI("end");
}

void RemoteMsgUtilFuzzTest(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t contextId = parcel.ReadUint64();
    std::string connectionName = parcel.ReadString();
    RemoteMsgUtil::GetConnectionName(contextId, connectionName);
    AuthParamInner authParam;
    Attributes attr;
    RemoteMsgUtil::EncodeAuthParam(authParam, attr);
    RemoteMsgUtil::DecodeAuthParam(attr, authParam);

    std::vector<ExecutorInfo> executorInfoArray1(1);
    std::vector<uint8_t> signedRemoteExecutorInfo1;
    Attributes attr1 = {};
    RemoteMsgUtil::EncodeQueryExecutorInfoReply(executorInfoArray1, signedRemoteExecutorInfo1, attr1);

    ExecutorInfo executorInfo2 = {};
    Attributes attr2 = {};
    std::vector<uint8_t> signedRemoteExecutorInfo2;
    RemoteMsgUtil::SetExecutorInfoToAttributes(executorInfo2, attr2);
    RemoteMsgUtil::GetExecutorInfoFromAttributes(attr2, signedRemoteExecutorInfo2, executorInfo2);

    ExecutorInfo executorInfo3 = {};
    Attributes attr3 = {};
    std::vector<uint8_t> signedRemoteExecutorInfo3;
    RemoteMsgUtil::SetExecutorInfoToAttributes(executorInfo3, attr3);
    RemoteMsgUtil::GetExecutorInfoFromAttributes(attr3, signedRemoteExecutorInfo3, executorInfo3);

    ExecutorInfo executorInfo4 = {};
    Attributes attr4 = {};
    std::vector<uint8_t> signedRemoteExecutorInfo4;
    RemoteMsgUtil::SetExecutorInfoToAttributes(executorInfo4, attr4);
    RemoteMsgUtil::GetExecutorInfoFromAttributes(attr4, signedRemoteExecutorInfo4, executorInfo4);

    ExecutorInfo executorInfo5 = {};
    Attributes attr5 = {};
    std::vector<uint8_t> signedRemoteExecutorInfo5;
    RemoteMsgUtil::SetExecutorInfoToAttributes(executorInfo5, attr5);
    RemoteMsgUtil::GetExecutorInfoFromAttributes(attr5, signedRemoteExecutorInfo5, executorInfo5);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzTest);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzTest,
    RemoteExecutorProxyFuzzTest,
    RemoteMsgUtilFuzzTest,
};

void RemoteExecutorStubFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs) / sizeof(FuzzFunc *));
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::RemoteExecutorStubFuzzTest(data, size);
    return 0;
}
