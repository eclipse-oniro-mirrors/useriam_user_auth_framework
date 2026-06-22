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

#include "user_auth_executor_fuzzer.h"

#include <cstdint>
#include <functional>

#include "executor.h"
#include "executor_mgr_wrapper.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_executor_iauth_executor_hdi.h"
#include "framework_executor_callback.h"
#include "collect_command.h"
#include "auth_command.h"
#include "enroll_command.h"
#include "identify_command.h"
#include "abandon_command.h"

#undef private

#define LOG_TAG "USER_AUTH_EXECUTOR"
#define LOG_FILE_ID LOG_FILE_EXECUTOR

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
using namespace std;
using namespace OHOS::UserIam::Common;
using namespace OHOS::UserIam::UserAuth;

vector<std::function<void(void)>> g_callbackToReply;
std::mutex g_callbackToReplyMutex;
std::shared_ptr<ExecutorRegisterCallback> g_executorCallback = nullptr;

class DummyAuthExecutorHdi : public IAuthExecutorHdi {
public:
    DummyAuthExecutorHdi() = default;
    ~DummyAuthExecutorHdi() override = default;

    ResultCode SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (fuzzParcel_ == nullptr) {
            return ResultCode::GENERAL_ERROR;
        }
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode GetExecutorInfo(ExecutorInfo &executorInfo) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // GetExecutorInfo is called in Executor constructor, when fuzzParcel_ is null
        // SUCCESS is returned to generate executor description
        if (fuzzParcel_ == nullptr) {
            return ResultCode::SUCCESS;
        }
        executorInfo.executorSensorHint = fuzzParcel_->ReadInt32();
        executorInfo.authType = static_cast<AuthType>(fuzzParcel_->ReadInt32());
        executorInfo.executorRole = static_cast<ExecutorRole>(fuzzParcel_->ReadInt32());
        executorInfo.executorMatcher = fuzzParcel_->ReadInt32();
        executorInfo.esl = static_cast<ExecutorSecureLevel>(fuzzParcel_->ReadInt32());
        FillFuzzUint8Vector(*fuzzParcel_, executorInfo.publicKey);
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (fuzzParcel_ == nullptr) {
            return ResultCode::GENERAL_ERROR;
        }
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Enroll(uint64_t scheduleId, const EnrollParam &param,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (fuzzParcel_ == nullptr) {
            return ResultCode::GENERAL_ERROR;
        }
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Authenticate(uint64_t scheduleId, const AuthenticateParam &param,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (fuzzParcel_ == nullptr) {
            return ResultCode::GENERAL_ERROR;
        }
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Identify(uint64_t scheduleId, const IdentifyParam &param,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (fuzzParcel_ == nullptr) {
            return ResultCode::GENERAL_ERROR;
        }
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Delete(const std::vector<uint64_t> &templateIdList) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (fuzzParcel_ == nullptr) {
            return ResultCode::GENERAL_ERROR;
        }
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Cancel(uint64_t scheduleId) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (fuzzParcel_ == nullptr) {
            return ResultCode::GENERAL_ERROR;
        }
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode SendCommand(PropertyMode commandId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (fuzzParcel_ == nullptr) {
            return ResultCode::GENERAL_ERROR;
        }
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode GetProperty(const std::vector<uint64_t> &templateIdList,
        const std::vector<Attributes::AttributeKey> &keys, Property &property) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (fuzzParcel_ == nullptr) {
            return ResultCode::GENERAL_ERROR;
        }
        property.authSubType = fuzzParcel_->ReadUint64();
        property.lockoutDuration = fuzzParcel_->ReadInt32();
        property.remainAttempts = fuzzParcel_->ReadInt32();
        property.enrollmentProgress = fuzzParcel_->ReadString();
        property.sensorInfo = fuzzParcel_->ReadString();
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode SetCachedTemplates(const std::vector<uint64_t> &templateIdList) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (fuzzParcel_ == nullptr) {
            return ResultCode::GENERAL_ERROR;
        }
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Abandon(uint64_t scheduleId, const DeleteParam &param,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (fuzzParcel_ == nullptr) {
            return ResultCode::GENERAL_ERROR;
        }
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    void SetParcel(const std::shared_ptr<Parcel> &parcel)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fuzzParcel_ = parcel;
    }

private:
    void FuzzTriggerIExecuteCallback(const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
    {
        auto reply = [fuzzParcel(this->fuzzParcel_), callbackObj]() {
            const uint32_t maxTriggerCount = 5;
            uint32_t triggerCount = fuzzParcel->ReadUint32() % maxTriggerCount;
            vector<uint8_t> extraInfo;
            for (uint32_t i = 0; i < triggerCount; i++) {
                FillFuzzUint8Vector(*fuzzParcel, extraInfo);
                bool triggerOnResult = fuzzParcel->ReadBool();
                if (triggerOnResult) {
                    callbackObj->OnAcquireInfo(fuzzParcel->ReadInt32(), extraInfo);
                } else {
                    callbackObj->OnResult(static_cast<ResultCode>(fuzzParcel->ReadInt32()), extraInfo);
                }
            }
        };

        bool instantReply = fuzzParcel_->ReadBool();
        if (instantReply) {
            reply();
        }
        bool delayedReply = fuzzParcel_->ReadBool();
        if (delayedReply) {
            std::lock_guard<std::mutex> guard(g_callbackToReplyMutex);
            g_callbackToReply.push_back(reply);
        }
    }
    std::mutex mutex_;
    std::shared_ptr<Parcel> fuzzParcel_ {nullptr};
};

class DummyExecutorMgrWrapper : public ExecutorMgrWrapper {
public:
    virtual ~DummyExecutorMgrWrapper() = default;
    uint64_t Register(const ExecutorInfo &info, std::shared_ptr<ExecutorRegisterCallback> callback) override
    {
        g_executorCallback = callback;
        return 0;
    }
};

class DummyExecutorMessenger : public ExecutorMessenger {
public:
    virtual ~DummyExecutorMessenger() = default;
    int32_t SendData(uint64_t scheduleId, ExecutorRole dstRole, const std::shared_ptr<AuthMessage> &msg) override
    {
        static_cast<void>(scheduleId);
        static_cast<void>(dstRole);
        static_cast<void>(msg);
        return fuzzParcel_->ReadInt32();
    }

    int32_t Finish(uint64_t scheduleId, int32_t resultCode, const Attributes &finalResult) override
    {
        static_cast<void>(scheduleId);
        static_cast<void>(resultCode);
        static_cast<void>(finalResult);
        return fuzzParcel_->ReadInt32();
    }

    void SetParcel(const std::shared_ptr<Parcel> &parcel)
    {
        fuzzParcel_ = parcel;
    }

private:
    std::shared_ptr<Parcel> fuzzParcel_;
};

auto g_executorHdi = UserIam::Common::MakeShared<DummyAuthExecutorHdi>();
auto g_executorMgrWrapper = UserIam::Common::MakeShared<DummyExecutorMgrWrapper>();
auto g_executor = UserIam::Common::MakeShared<Executor>(g_executorMgrWrapper, g_executorHdi, 1);
auto g_executorMessenger = UserIam::Common::MakeShared<DummyExecutorMessenger>();

void FuzzExecutorResetExecutor(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    static uint32_t id = 0;
    id++;
    g_executor = UserIam::Common::MakeShared<Executor>(g_executorMgrWrapper, g_executorHdi, id);
    IAM_LOGI("end");
}

void FuzzExecutorOnHdiDisconnect(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    static int32_t skip_count = 1000;
    // OnHdiDisconnect affects test of other function, skip it in the first phase
    if (skip_count > 0) {
        skip_count--;
        return;
    }
    g_executor->OnHdiDisconnect();
    g_executorCallback = nullptr;
    IAM_LOGI("end");
}

void FuzzExecutorRegister(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    g_executor->Register();
    IAM_LOGI("end");
}

void FuzzExecutorGetExecutorHdi(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    g_executor->GetExecutorHdi();
    IAM_LOGI("end");
}

void FuzzExecutorGetDescription(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    g_executor->GetDescription();
    IAM_LOGI("end");
}

void FuzzExecutorUnregisterExecutorCallback(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    g_executor->UnregisterExecutorCallback();
    IAM_LOGI("end");
}

void FuzzExecutorRespondCallbackOnDisconnect(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    g_executor->RespondCallbackOnDisconnect();
    IAM_LOGI("end");
}

void FuzzExecutorGetAuthType(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    g_executor->GetAuthType();
    IAM_LOGI("end");
}

void FuzzExecutorGetExecutorRole(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    g_executor->GetExecutorRole();
    IAM_LOGI("end");
}

void FillIExecutorMessenger(std::shared_ptr<Parcel> parcel, shared_ptr<ExecutorMessenger> &messenger)
{
    bool fillNull = parcel->ReadBool();
    if (fillNull) {
        messenger = nullptr;
        return;
    }
    messenger = g_executorMessenger;
}

void FillIAttributes(std::shared_ptr<Parcel> parcel, Attributes &attributes)
{
    bool fillNull = parcel->ReadBool();
    if (fillNull) {
        return;
    }

    attributes.SetUint64Value(Attributes::ATTR_TEMPLATE_ID, parcel->ReadUint64());
    attributes.SetUint64Value(Attributes::ATTR_CALLER_UID, parcel->ReadUint64());
    attributes.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, parcel->ReadUint32());
    std::vector<uint64_t> templateIdList;
    FillFuzzUint64Vector(*parcel, templateIdList);
    attributes.GetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIdList);
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(*parcel, extraInfo);
    attributes.GetUint64ArrayValue(Attributes::ATTR_EXTRA_INFO, templateIdList);
    attributes.SetUint64Value(Attributes::ATTR_CALLER_UID, parcel->ReadUint64());
    attributes.SetUint32Value(Attributes::ATTR_SCHEDULE_MODE, parcel->ReadUint32());
}

void FuzzExecutorCommand(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    uint64_t scheduleId = parcel->ReadUint64();
    Attributes properties;
    FillIAttributes(parcel, properties);
    std::shared_ptr<IAsyncCommand> command =
        Common::MakeShared<CollectCommand>(g_executor, scheduleId, properties, g_executorMessenger);
    g_executor->AddCommand(command);
    g_executor->RemoveCommand(command);
    IAM_LOGI("end");
}

void FuzzFrameworkOnMessengerReady(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_executorCallback may be not set
    if (g_executorCallback == nullptr) {
        return;
    }
    shared_ptr<ExecutorMessenger> messenger = nullptr;
    FillIExecutorMessenger(parcel, messenger);
    std::vector<uint8_t> publicKey;
    FillFuzzUint8Vector(*parcel, publicKey);
    std::vector<uint64_t> templateIds;
    FillFuzzUint64Vector(*parcel, templateIds);
    g_executorCallback->OnMessengerReady(messenger, publicKey, templateIds);
    IAM_LOGI("end");
}

void FuzzFrameworkOnBeginExecute(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_executorCallback may be not set
    if (g_executorCallback == nullptr) {
        return;
    }
    uint64_t scheduleId = parcel->ReadUint64();
    std::vector<uint8_t> publicKey;
    FillFuzzUint8Vector(*parcel, publicKey);
    Attributes commandAttrs;
    FillIAttributes(parcel, commandAttrs);
    g_executorCallback->OnBeginExecute(scheduleId, publicKey, commandAttrs);
    IAM_LOGI("end");
}

void FuzzFrameworkOnEndExecute(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_executorCallback may be not set
    if (g_executorCallback == nullptr) {
        return;
    }
    uint64_t scheduleId = parcel->ReadUint64();
    Attributes consumerAttr;
    FillIAttributes(parcel, consumerAttr);
    g_executorCallback->OnEndExecute(scheduleId, consumerAttr);
    IAM_LOGI("end");
}

void FuzzFrameworkOnSetProperty(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_executorCallback may be not set
    if (g_executorCallback == nullptr) {
        return;
    }
    Attributes properties;
    FillIAttributes(parcel, properties);
    g_executorCallback->OnSetProperty(properties);
    IAM_LOGI("end");
}

void FuzzFrameworkOnGetProperty(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_executorCallback may be not set
    if (g_executorCallback == nullptr) {
        return;
    }
    Attributes conditions;
    FillIAttributes(parcel, conditions);
    Attributes values;
    FillIAttributes(parcel, values);
    g_executorCallback->OnGetProperty(conditions, values);
    IAM_LOGI("end");
}

void FuzzTriggerCallback(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    std::lock_guard<std::mutex> guard(g_callbackToReplyMutex);
    IAM_LOGI("trigger callback num %{public}zu", g_callbackToReply.size());
    for (const auto &reply : g_callbackToReply) {
        reply();
    }
    g_callbackToReply.clear();
    IAM_LOGI("end");
}

std::shared_ptr<FrameworkExecutorCallback> g_frameworkExecutorCallback =
    UserIam::Common::MakeShared<FrameworkExecutorCallback>(g_executor);

void FuzzFrameworkExecutorOnMessengerReady(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_executorCallback may be not set
    if (g_frameworkExecutorCallback == nullptr) {
        return;
    }
    shared_ptr<ExecutorMessenger> messenger = nullptr;
    FillIExecutorMessenger(parcel, messenger);
    std::vector<uint8_t> publicKey;
    FillFuzzUint8Vector(*parcel, publicKey);
    std::vector<uint64_t> templateIds;
    FillFuzzUint64Vector(*parcel, templateIds);
    g_frameworkExecutorCallback->OnMessengerReady(messenger, publicKey, templateIds);
    IAM_LOGI("end");
}

void FuzzFrameworkExecutorOnBeginExecute(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_executorCallback may be not set
    if (g_frameworkExecutorCallback == nullptr) {
        return;
    }
    uint64_t scheduleId = parcel->ReadUint64();
    std::vector<uint8_t> publicKey;
    FillFuzzUint8Vector(*parcel, publicKey);
    Attributes commandAttrs;
    FillIAttributes(parcel, commandAttrs);
    g_frameworkExecutorCallback->OnBeginExecute(scheduleId, publicKey, commandAttrs);
    IAM_LOGI("end");
}

void FuzzFrameworkExecutorOnEndExecute(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_frameworkExecutorCallback may be not set
    if (g_frameworkExecutorCallback == nullptr) {
        return;
    }
    uint64_t scheduleId = parcel->ReadUint64();
    Attributes consumerAttr;
    FillIAttributes(parcel, consumerAttr);
    g_frameworkExecutorCallback->OnEndExecute(scheduleId, consumerAttr);
    IAM_LOGI("end");
}

void FuzzFrameworkExecutorOnSetProperty(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_frameworkExecutorCallback may be not set
    if (g_frameworkExecutorCallback == nullptr) {
        return;
    }
    Attributes properties;
    FillIAttributes(parcel, properties);
    g_frameworkExecutorCallback->OnSetProperty(properties);
    IAM_LOGI("end");
}

void FuzzFrameworkExecutorOnGetProperty(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_frameworkExecutorCallback may be not set
    if (g_frameworkExecutorCallback == nullptr) {
        return;
    }
    Attributes conditions;
    FillIAttributes(parcel, conditions);
    Attributes values;
    FillIAttributes(parcel, values);
    g_frameworkExecutorCallback->OnGetProperty(conditions, values);
    IAM_LOGI("end");
}

void FuzzFrameworkExecutorOnSendData(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_frameworkExecutorCallback may be not set
    if (g_frameworkExecutorCallback == nullptr) {
        return;
    }
    uint64_t scheduleId = parcel->ReadUint64();
    Attributes data;
    FillIAttributes(parcel, data);
    g_frameworkExecutorCallback->OnSendData(scheduleId, data);
    IAM_LOGI("end");
}

void FuzzFrameworkExecutorProcessEnrollCommand(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_frameworkExecutorCallback may be not set
    if (g_frameworkExecutorCallback == nullptr) {
        return;
    }
    uint64_t scheduleId = parcel->ReadUint64();
    Attributes properties;
    FillIAttributes(parcel, properties);
    g_frameworkExecutorCallback->ProcessEnrollCommand(scheduleId, properties);
    IAM_LOGI("end");
}

void FuzzFrameworkExecutorProcessAuthCommand(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_frameworkExecutorCallback may be not set
    if (g_frameworkExecutorCallback == nullptr) {
        return;
    }
    uint64_t scheduleId = parcel->ReadUint64();
    Attributes properties;
    FillIAttributes(parcel, properties);
    g_frameworkExecutorCallback->ProcessAuthCommand(scheduleId, properties);
    IAM_LOGI("end");
}

void FuzzFrameworkExecutorProcessIdentifyCommand(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_frameworkExecutorCallback may be not set
    if (g_frameworkExecutorCallback == nullptr) {
        return;
    }
    uint64_t scheduleId = parcel->ReadUint64();
    Attributes properties;
    FillIAttributes(parcel, properties);
    g_frameworkExecutorCallback->ProcessIdentifyCommand(scheduleId, properties);
    IAM_LOGI("end");
}

void FuzzFrameworkExecutorProcessCancelCommand(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_frameworkExecutorCallback may be not set
    if (g_frameworkExecutorCallback == nullptr) {
        return;
    }
    uint64_t scheduleId = parcel->ReadUint64();
    g_frameworkExecutorCallback->ProcessCancelCommand(scheduleId);
    IAM_LOGI("end");
}

void FuzzFrameworkExecutorProcessTemplateCommand(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_frameworkExecutorCallback may be not set
    if (g_frameworkExecutorCallback == nullptr) {
        return;
    }
    Attributes properties;
    FillIAttributes(parcel, properties);
    g_frameworkExecutorCallback->ProcessDeleteTemplateCommand(properties);
    g_frameworkExecutorCallback->ProcessSetCachedTemplates(properties);
    IAM_LOGI("end");
}

void FuzzFrameworkExecutorProcessNotifyExecutorReady(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_frameworkExecutorCallback may be not set
    if (g_frameworkExecutorCallback == nullptr) {
        return;
    }
    Attributes properties;
    FillIAttributes(parcel, properties);
    g_frameworkExecutorCallback->ProcessNotifyExecutorReady(properties);
    IAM_LOGI("end");
}

void FuzzFrameworkExecutorProcessCustomCommand(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_frameworkExecutorCallback may be not set
    if (g_frameworkExecutorCallback == nullptr) {
        return;
    }
    Attributes properties;
    FillIAttributes(parcel, properties);
    g_frameworkExecutorCallback->ProcessCustomCommand(properties);
    IAM_LOGI("end");
}

void FuzzFrameworkExecutorProcessGetPropertyCommand(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_frameworkExecutorCallback may be not set
    if (g_frameworkExecutorCallback == nullptr) {
        return;
    }
    std::shared_ptr<Attributes> conditions = UserIam::Common::MakeShared<Attributes>();
    std::shared_ptr<Attributes> values = UserIam::Common::MakeShared<Attributes>();
    g_frameworkExecutorCallback->ProcessGetPropertyCommand(conditions, values);
    IAM_LOGI("end");
}

void FuzzAuthCommandOnResultInner(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    uint64_t scheduleId = parcel->ReadUint64();
    Attributes attributes;
    FillIAttributes(parcel, attributes);
    ResultCode result = static_cast<ResultCode>(parcel->ReadInt32());
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(*parcel, extraInfo);
    shared_ptr<ExecutorMessenger> messenger = nullptr;
    FillIExecutorMessenger(parcel, messenger);
    auto command = Common::MakeShared<AuthCommand>(g_executor, scheduleId, attributes, messenger);
    if (command == nullptr) {
        IAM_LOGE("command is null");
        return;
    }
    command->OnResult(result, extraInfo);
    IAM_LOGI("end");
}

void FuzzEnrollCommandOnResultInner(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    uint64_t scheduleId = parcel->ReadUint64();
    Attributes attributes;
    FillIAttributes(parcel, attributes);
    ResultCode result = static_cast<ResultCode>(parcel->ReadInt32());
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(*parcel, extraInfo);
    shared_ptr<ExecutorMessenger> messenger = nullptr;
    FillIExecutorMessenger(parcel, messenger);
    auto command = Common::MakeShared<EnrollCommand>(g_executor, scheduleId, attributes, messenger);
    if (command == nullptr) {
        IAM_LOGE("command is null");
        return;
    }
    command->OnResult(result, extraInfo);
    IAM_LOGI("end");
}

void FuzzIdentifyCommandOnResultInner(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    uint64_t scheduleId = parcel->ReadUint64();
    Attributes attributes;
    FillIAttributes(parcel, attributes);
    ResultCode result = static_cast<ResultCode>(parcel->ReadInt32());
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(*parcel, extraInfo);
    shared_ptr<ExecutorMessenger> messenger = nullptr;
    FillIExecutorMessenger(parcel, messenger);
    auto command = Common::MakeShared<IdentifyCommand>(g_executor, scheduleId, attributes, messenger);
    if (command == nullptr) {
        IAM_LOGE("command is null");
        return;
    }
    command->OnResult(result, extraInfo);
    IAM_LOGI("end");
}

void FuzzCollectCommandOnResultInner(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    uint64_t scheduleId = parcel->ReadUint64();
    Attributes attributes;
    FillIAttributes(parcel, attributes);
    ResultCode result = static_cast<ResultCode>(parcel->ReadInt32());
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(*parcel, extraInfo);
    shared_ptr<ExecutorMessenger> messenger = nullptr;
    FillIExecutorMessenger(parcel, messenger);
    auto command = Common::MakeShared<CollectCommand>(g_executor, scheduleId, attributes, messenger);
    if (command == nullptr) {
        IAM_LOGE("command is null");
        return;
    }
    command->OnResult(result, extraInfo);
    IAM_LOGI("end");
}

void FuzzAbandonCommandOnResultInner(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    uint64_t scheduleId = parcel->ReadUint64();
    Attributes attributes;
    FillIAttributes(parcel, attributes);
    ResultCode result = static_cast<ResultCode>(parcel->ReadInt32());
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(*parcel, extraInfo);
    shared_ptr<ExecutorMessenger> messenger = nullptr;
    FillIExecutorMessenger(parcel, messenger);
    auto command = Common::MakeShared<AbandonCommand>(g_executor, scheduleId, attributes, messenger);
    if (command == nullptr) {
        IAM_LOGE("command is null");
        return;
    }
    command->OnResult(result, extraInfo);
    IAM_LOGI("end");
}

void FillAuthCommandAttributes(std::shared_ptr<Parcel> parcel, Attributes &attributes)
{
    bool fillNull = parcel->ReadBool();
    if (fillNull) {
        return;
    }

    bool setTemplateIdList = parcel->ReadBool();
    if (setTemplateIdList) {
        std::vector<uint64_t> templateIdList;
        FillFuzzUint64Vector(*parcel, templateIdList);
        attributes.SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIdList);
    }

    bool setTokenId = parcel->ReadBool();
    if (setTokenId) {
        attributes.SetUint32Value(Attributes::ATTR_ACCESS_TOKEN_ID, parcel->ReadUint32());
    }

    bool setEndAfterFirstFail = parcel->ReadBool();
    if (setEndAfterFirstFail) {
        attributes.SetBoolValue(Attributes::ATTR_END_AFTER_FIRST_FAIL, parcel->ReadBool());
    }

    bool setExtraInfo = parcel->ReadBool();
    if (setExtraInfo) {
        std::vector<uint8_t> extraInfo;
        FillFuzzUint8Vector(*parcel, extraInfo);
        attributes.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, extraInfo);
    }

    bool setAuthIntent = parcel->ReadBool();
    if (setAuthIntent) {
        attributes.SetInt32Value(Attributes::ATTR_AUTH_INTENTION, parcel->ReadInt32());
    }

    bool setUserId = parcel->ReadBool();
    if (setUserId) {
        attributes.SetInt32Value(Attributes::ATTR_USER_ID, parcel->ReadInt32());
    }

    bool setAuthScene = parcel->ReadBool();
    if (setAuthScene) {
        attributes.SetInt32Value(Attributes::ATTR_AUTH_SCENE, parcel->ReadInt32());
    }

    bool setTitle = parcel->ReadBool();
    if (setTitle) {
        std::string title;
        FillFuzzString(*parcel, title);
        attributes.SetStringValue(Attributes::ATTR_WIDGET_TITLE, title);
    }
}

void FuzzAuthCommandSendRequest(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    uint64_t scheduleId = parcel->ReadUint64();
    Attributes attributes;
    FillAuthCommandAttributes(parcel, attributes);
    shared_ptr<ExecutorMessenger> messenger = nullptr;
    FillIExecutorMessenger(parcel, messenger);
    auto command = Common::MakeShared<AuthCommand>(g_executor, scheduleId, attributes, messenger);
    if (command == nullptr) {
        IAM_LOGE("command is null");
        return;
    }
    g_executor->AddCommand(command);
    command->StartProcess();
    IAM_LOGI("end");
}

void FuzzFillPropertyToAttribute(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_frameworkExecutorCallback may be not set
    if (g_frameworkExecutorCallback == nullptr) {
        return;
    }
    std::vector<Attributes::AttributeKey> keyList = {
        Attributes::ATTR_PIN_SUB_TYPE,
        Attributes::ATTR_FREEZING_TIME,
        Attributes::ATTR_REMAIN_TIMES,
        Attributes::ATTR_ENROLL_PROGRESS,
        Attributes::ATTR_SENSOR_INFO,
        Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION,
        Attributes::ATTR_CAMERA_STATUS,
        Attributes::ATTR_ROOT
    };
    Property property = {};
    std::shared_ptr<Attributes> values = UserIam::Common::MakeShared<Attributes>();
    g_frameworkExecutorCallback->FillPropertyToAttribute(keyList, property, values);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzFrameworkOnGetProperty);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzExecutorResetExecutor,
    FuzzExecutorOnHdiDisconnect,
    FuzzExecutorRegister,
    FuzzExecutorGetExecutorHdi,
    FuzzExecutorGetDescription,
    FuzzExecutorUnregisterExecutorCallback,
    FuzzExecutorRespondCallbackOnDisconnect,
    FuzzExecutorGetAuthType,
    FuzzExecutorGetExecutorRole,
    FuzzExecutorCommand,
    FuzzFrameworkOnMessengerReady,
    FuzzFrameworkOnBeginExecute,
    FuzzFrameworkOnEndExecute,
    FuzzFrameworkOnSetProperty,
    FuzzFrameworkOnGetProperty,
    FuzzTriggerCallback,
    FuzzFrameworkExecutorOnMessengerReady,
    FuzzFrameworkExecutorOnBeginExecute,
    FuzzFrameworkExecutorOnEndExecute,
    FuzzFrameworkExecutorOnSetProperty,
    FuzzFrameworkExecutorOnGetProperty,
    FuzzFrameworkExecutorOnSendData,
    FuzzFrameworkExecutorProcessEnrollCommand,
    FuzzFrameworkExecutorProcessAuthCommand,
    FuzzFrameworkExecutorProcessIdentifyCommand,
    FuzzFrameworkExecutorProcessCancelCommand,
    FuzzFrameworkExecutorProcessTemplateCommand,
    FuzzFrameworkExecutorProcessNotifyExecutorReady,
    FuzzFrameworkExecutorProcessCustomCommand,
    FuzzFrameworkExecutorProcessGetPropertyCommand,
    FuzzFillPropertyToAttribute,
    FuzzAuthCommandOnResultInner,
    FuzzEnrollCommandOnResultInner,
    FuzzIdentifyCommandOnResultInner,
    FuzzCollectCommandOnResultInner,
    FuzzAbandonCommandOnResultInner,
    FuzzAuthCommandSendRequest,
};

void UserAuthExecutorFuzzTest(const uint8_t *data, size_t size)
{
    auto parcel = UserIam::Common::MakeShared<Parcel>();
    if (parcel == nullptr) {
        IAM_LOGI("parcel is null");
        return;
    }
    parcel->WriteBuffer(data, size);
    parcel->RewindRead(0);
    uint32_t index = parcel->ReadUint32() % (sizeof(g_fuzzFuncs)) / sizeof(FuzzFunc *);
    g_executorHdi->SetParcel(parcel);
    g_executorMessenger->SetParcel(parcel);
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::UserAuthExecutorFuzzTest(data, size);
    return 0;
}
