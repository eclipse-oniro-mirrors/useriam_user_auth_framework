/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "executor_callback_service.h"
#include "executor_callback_service_fuzzer.h"
#include "executor_messenger_client.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "AUTH_EXECUTOR_MGR_SDK"
#define LOG_FILE_ID LOG_FILE_EXECUTOR_CALLBACK_SERVICE

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyExecutorRegisterCallback final : public ExecutorRegisterCallback {
public:
    void OnMessengerReady(const std::shared_ptr<ExecutorMessenger> &messenger,
        const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIds)
    {
        IAM_LOGI("start");
        static_cast<void>(messenger);
        static_cast<void>(publicKey);
        static_cast<void>(templateIds);
    }

    int32_t OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &commandAttrs)
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(publicKey);
        static_cast<void>(commandAttrs);
        return SUCCESS;
    }

    int32_t OnEndExecute(uint64_t scheduleId, const Attributes &commandAttrs)
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(commandAttrs);
        return SUCCESS;
    }

    int32_t OnSetProperty(const Attributes &properties)
    {
        IAM_LOGI("start");
        static_cast<void>(properties);
        return SUCCESS;
    }

    int32_t OnGetProperty(const Attributes &conditions, Attributes &results)
    {
        IAM_LOGI("start");
        static_cast<void>(conditions);
        static_cast<void>(results);
        return SUCCESS;
    }

    int32_t OnSendData(uint64_t scheduleId, const Attributes &data)
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(data);
        return SUCCESS;
    }
};

class DummyExecutorMessenger final : public IExecutorMessenger {
public:
    int32_t SendData(uint64_t scheduleId, int32_t dstRole,
        const std::vector<uint8_t> &msg) override
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(dstRole);
        static_cast<void>(msg);
        return SUCCESS;
    }

    int32_t Finish(uint64_t scheduleId, int32_t resultCode, const std::vector<uint8_t> &finalResult) override
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(resultCode);
        static_cast<void>(finalResult);
        return SUCCESS;
    }

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }
};

std::shared_ptr<ExecutorCallbackService> CreateExecutorCallbackService()
{
    std::shared_ptr<ExecutorRegisterCallback> testCallback = Common::MakeShared<DummyExecutorRegisterCallback>();
    return Common::MakeShared<ExecutorCallbackService>(testCallback);
}

void FuzzOnMessengerReady(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto service = CreateExecutorCallbackService();
    sptr<IExecutorMessenger> messenger(new (std::nothrow) DummyExecutorMessenger());
    std::vector<uint8_t> publicKey;
    Common::FillFuzzUint8Vector(parcel, publicKey);
    std::vector<uint64_t> templateIdList;
    Common::FillFuzzUint64Vector(parcel, templateIdList);
    service->OnMessengerReady(messenger, publicKey, templateIdList);
    IAM_LOGI("end");
}

void FuzzOnBeginExecute(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto service = CreateExecutorCallbackService();
    uint64_t scheduleId = parcel.ReadUint64();
    std::vector<uint8_t> publicKey;
    Common::FillFuzzUint8Vector(parcel, publicKey);
    std::vector<uint8_t> command;
    Common::FillFuzzUint8Vector(parcel, command);
    service->OnBeginExecute(scheduleId, publicKey, command);
    IAM_LOGI("end");
}

void FuzzOnEndExecute(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto service = CreateExecutorCallbackService();
    uint64_t scheduleId = parcel.ReadUint64();
    std::vector<uint8_t> command;
    Common::FillFuzzUint8Vector(parcel, command);
    service->OnEndExecute(scheduleId, command);
    IAM_LOGI("end");
}

void FuzzOnSetProperty(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto service = CreateExecutorCallbackService();
    std::vector<uint8_t> properties;
    Common::FillFuzzUint8Vector(parcel, properties);
    service->OnSetProperty(properties);
    IAM_LOGI("end");
}

void FuzzOnGetProperty(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto service = CreateExecutorCallbackService();
    std::vector<uint8_t> condition;
    Common::FillFuzzUint8Vector(parcel, condition);
    std::vector<uint8_t> values;
    Common::FillFuzzUint8Vector(parcel, values);
    service->OnGetProperty(condition, values);
    IAM_LOGI("end");
}

void FuzzOnSendData(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto service = CreateExecutorCallbackService();
    uint64_t scheduleId = parcel.ReadUint64();
    std::vector<uint8_t> extraInfo;
    Common::FillFuzzUint8Vector(parcel, extraInfo);
    service->OnSendData(scheduleId, extraInfo);
    IAM_LOGI("end");
}

void FuzzCallbackEnter(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto service = CreateExecutorCallbackService();
    uint32_t code = parcel.ReadUint32();
    service->CallbackEnter(code);
    IAM_LOGI("end");
}

void FuzzCallbackExit(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto service = CreateExecutorCallbackService();
    uint32_t code = parcel.ReadUint32();
    int32_t result = parcel.ReadInt32();
    service->CallbackExit(code, result);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzOnMessengerReady);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzOnMessengerReady,
    FuzzOnBeginExecute,
    FuzzOnEndExecute,
    FuzzOnSetProperty,
    FuzzOnGetProperty,
    FuzzOnSendData,
    FuzzCallbackEnter,
    FuzzCallbackExit,
};

void ExecutorCallbackServiceFuzzTest(const uint8_t *data, size_t size)
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
    OHOS::UserIam::UserAuth::ExecutorCallbackServiceFuzzTest(data, size);
    return 0;
}