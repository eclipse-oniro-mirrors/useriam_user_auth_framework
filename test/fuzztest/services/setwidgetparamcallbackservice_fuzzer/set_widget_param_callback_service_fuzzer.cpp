/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "set_widget_param_callback_service.h"
#include "set_widget_param_callback_service_fuzzer.h"
#include "context_pool.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyContext final : public Context {
public:
    ~DummyContext() override = default;

    bool Start() override
    {
        IAM_LOGI("start");
        return true;
    }

    bool Stop() override
    {
        IAM_LOGI("stop");
        return true;
    }

    uint64_t GetContextId() const override
    {
        return contextId_;
    }

    ContextType GetContextType() const override
    {
        return ContextType::CONTEXT_SIMPLE_AUTH;
    }

    std::shared_ptr<ScheduleNode> GetScheduleNode(uint64_t scheduleId) const override
    {
        static_cast<void>(scheduleId);
        return nullptr;
    }

    int32_t GetLatestError() const override
    {
        return SUCCESS;
    }

    uint32_t GetTokenId() const override
    {
        return 0;
    }

    int32_t GetUserId() const override
    {
        return 0;
    }

    int32_t GetAuthType() const override
    {
        return 0;
    }

    std::string GetCallerName() const override
    {
        return "";
    }

    void SetRemoteAuthParam(const WidgetParamInner &widgetParam, const sptr<IModalCallback> &modalCallback) override
    {
        IAM_LOGI("start");
        static_cast<void>(widgetParam);
        static_cast<void>(modalCallback);
    }

    uint64_t contextId_ = 0;

protected:
    void SetLatestError(int32_t error) override
    {
        static_cast<void>(error);
    }
};

std::shared_ptr<SetWidgetParamCallbackService> CreateSetWidgetParamCallbackService(uint64_t contextId)
{
    auto context = Common::MakeShared<DummyContext>();
    if (context != nullptr) {
        context->contextId_ = contextId;
        ContextPool::Instance().Insert(context);
    }
    return Common::MakeShared<SetWidgetParamCallbackService>(contextId);
}

void FuzzOnSetRemoteAuthWidgetParam(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t contextId = parcel.ReadUint64();
    auto service = CreateSetWidgetParamCallbackService(contextId);
    if (service == nullptr) {
        IAM_LOGE("service is null");
        return;
    }

    IpcWidgetParamInner ipcWidgetParamInner = {};
    Common::FillFuzzString(parcel, ipcWidgetParamInner.title);
    Common::FillFuzzString(parcel, ipcWidgetParamInner.navigationButtonText);
    ipcWidgetParamInner.windowMode = parcel.ReadInt32();
    ipcWidgetParamInner.hasContext = parcel.ReadBool();
    sptr<IModalCallback> testModalCallback = nullptr;

    service->OnSetRemoteAuthWidgetParam(ipcWidgetParamInner, testModalCallback);
    ContextPool::Instance().Delete(contextId);
    IAM_LOGI("end");
}

void FuzzCallbackEnter(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t contextId = parcel.ReadUint64();
    auto service = CreateSetWidgetParamCallbackService(contextId);
    if (service == nullptr) {
        IAM_LOGE("service is null");
        return;
    }
    uint32_t code = parcel.ReadUint32();
    service->CallbackEnter(code);
    ContextPool::Instance().Delete(contextId);
    IAM_LOGI("end");
}

void FuzzCallbackExit(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t contextId = parcel.ReadUint64();
    auto service = CreateSetWidgetParamCallbackService(contextId);
    if (service == nullptr) {
        IAM_LOGE("service is null");
        return;
    }
    uint32_t code = parcel.ReadUint32();
    int32_t result = parcel.ReadInt32();
    service->CallbackExit(code, result);
    ContextPool::Instance().Delete(contextId);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzOnSetRemoteAuthWidgetParam);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzOnSetRemoteAuthWidgetParam,
    FuzzCallbackEnter,
    FuzzCallbackExit,
};

void SetWidgetParamCallbackServiceFuzzTest(const uint8_t *data, size_t size)
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
    OHOS::UserIam::UserAuth::SetWidgetParamCallbackServiceFuzzTest(data, size);
    return 0;
}
