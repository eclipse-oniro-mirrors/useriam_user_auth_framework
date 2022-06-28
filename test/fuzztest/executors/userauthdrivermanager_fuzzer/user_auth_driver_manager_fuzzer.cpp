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

#include "user_auth_driver_manager_fuzzer.h"

#include <cstdint>

#include "driver_manager.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iauth_driver_hdi.h"
#include "iauth_executor_hdi.h"

#undef private

#define LOG_LABEL Common::LABEL_USER_AUTH_EXECUTOR

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
namespace {
using namespace std;
using namespace OHOS::UserIAM;
using namespace OHOS::UserIAM::Common;
class DummyAuthExecutorHdi : public IAuthExecutorHdi {
public:
    DummyAuthExecutorHdi() = default;
    ~DummyAuthExecutorHdi() override = default;

    ResultCode GetExecutorInfo(ExecutorInfo &executorInfo) override
    {
        // GetExecutorInfo is called in Executor constructor, when fuzzParcel_ is null
        // SUCCESS is returned to generate executor description
        if (fuzzParcel_ == nullptr) {
            return ResultCode::SUCCESS;
        }
        executorInfo.executorId = fuzzParcel_->ReadInt32();
        executorInfo.authType = static_cast<AuthType>(fuzzParcel_->ReadInt32());
        executorInfo.role = static_cast<ExecutorRole>(fuzzParcel_->ReadInt32());
        executorInfo.executorType = fuzzParcel_->ReadInt32();
        executorInfo.esl = static_cast<ExecutorSecureLevel>(fuzzParcel_->ReadInt32());
        FillFuzzUint8Vector(*fuzzParcel_, executorInfo.publicKey);
        FillFuzzUint8Vector(*fuzzParcel_, executorInfo.deviceId);
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode GetTemplateInfo(uint64_t templateId, UserAuth::TemplateInfo &templateInfo) override
    {
        templateInfo.executorType = fuzzParcel_->ReadUint32();
        templateInfo.freezingTime = fuzzParcel_->ReadInt32();
        templateInfo.remainTimes = fuzzParcel_->ReadInt32();
        FillFuzzUint8Vector(*fuzzParcel_, templateInfo.extraInfo);
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo) override
    {
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Enroll(uint64_t scheduleId, uint64_t callerUid, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override
    {
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Authenticate(uint64_t scheduleId, uint64_t callerUid, const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &extraInfo, const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override
    {
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Identify(uint64_t scheduleId, uint64_t callerUid, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override
    {
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Delete(const std::vector<uint64_t> &templateIdList) override
    {
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Cancel(uint64_t scheduleId) override
    {
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode SendCommand(UserAuth::AuthPropertyMode commandId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override
    {
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    void SetParcel(std::shared_ptr<Parcel> &parcel)
    {
        fuzzParcel_ = parcel;
    }

private:
    std::shared_ptr<Parcel> fuzzParcel_ = nullptr;
};

auto g_executorHdi = Common::MakeShared<DummyAuthExecutorHdi>();

class DummyAuthDriverHdi : public IAuthDriverHdi {
public:
    DummyAuthDriverHdi() = default;
    virtual ~DummyAuthDriverHdi() = default;

    void GetExecutorList(std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> &executorList)
    {
        static const uint32_t max_num = 20;
        uint32_t num = fuzzParcel_->ReadUint32();
        uint32_t executorNum = num % max_num;
        for (uint32_t i = 0; i < executorNum; i++) {
            bool isNull = fuzzParcel_->ReadBool();
            if (isNull) {
                executorList.push_back(nullptr);
                continue;
            }
            executorList.push_back(g_executorHdi);
        }
        return;
    }

    void SetParcel(std::shared_ptr<Parcel> &parcel)
    {
        fuzzParcel_ = parcel;
    }

private:
    std::shared_ptr<Parcel> fuzzParcel_;
};

auto g_authDriverHdi = Common::MakeShared<DummyAuthDriverHdi>();
const std::map<std::string, UserAuth::HdiConfig> g_hdiName2Config = {
    {"face_auth_interface_service", {1, g_authDriverHdi}}, {"pin_auth_interface_service", {2, g_authDriverHdi}}};
const string g_serviceNames[] = {"face_auth_interface_service", "pin_auth_interface_service"};

void FuzzStart(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // driver manager forbids multiple invoke of Start(), it's config must be valid
    Singleton<UserAuth::DriverManager>::GetInstance().Start(g_hdiName2Config);
    IAM_LOGI("end");
}

void FuzzOnFrameworkReady(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    Singleton<UserAuth::DriverManager>::GetInstance().OnFrameworkReady();
    IAM_LOGI("end");
}

void FuzzOnAllHdiDisconnect(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    Singleton<UserAuth::DriverManager>::GetInstance().OnAllHdiDisconnect();
    IAM_LOGI("end");
}

void FuzzSubscribeHdiDriverStatus(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    Singleton<UserAuth::DriverManager>::GetInstance().SubscribeHdiDriverStatus();
    IAM_LOGI("end");
}

void FuzzGetDriverByServiceName(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    std::string serviceName;
    parcel->ReadString(serviceName);
    Singleton<UserAuth::DriverManager>::GetInstance().GetDriverByServiceName(serviceName);
    IAM_LOGI("end");
}

void FuzzDriverConnect(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    uint32_t index = parcel->ReadUint32() % (sizeof(g_serviceNames) / sizeof(g_serviceNames[0]));
    std::shared_ptr<Driver> driver =
        Singleton<UserAuth::DriverManager>::GetInstance().GetDriverByServiceName(g_serviceNames[index]);
    // Since config is valid, GetDriverByServiceName should never return null.
    // If it happens to be null, let fuzz process crash.
    driver->OnHdiConnect();
    IAM_LOGI("end");
}

void FuzzDriverDisconnect(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    uint32_t index = parcel->ReadUint32() % (sizeof(g_serviceNames) / sizeof(g_serviceNames[0]));
    std::shared_ptr<Driver> driver =
        Singleton<UserAuth::DriverManager>::GetInstance().GetDriverByServiceName(g_serviceNames[index]);
    // Since config is valid, GetDriverByServiceName should never return null.
    // If it happens to be null, let fuzz process crash.
    driver->OnHdiDisconnect();
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzGetDriverByServiceName);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzStart,
    FuzzOnFrameworkReady,
    FuzzOnAllHdiDisconnect,
    FuzzSubscribeHdiDriverStatus,
    FuzzGetDriverByServiceName,
    FuzzDriverConnect,
    FuzzDriverDisconnect,
};

void UserAuthDriverManagerFuzzTest(const uint8_t *data, size_t size)
{
    auto parcel = Common::MakeShared<Parcel>();
    if (parcel == nullptr) {
        IAM_LOGI("parcel is null");
        return;
    }
    parcel->WriteBuffer(data, size);
    parcel->RewindRead(0);
    uint32_t index = parcel->ReadUint32() % (sizeof(g_fuzzFuncs)) / sizeof(FuzzFunc *);
    g_executorHdi->SetParcel(parcel);
    g_authDriverHdi->SetParcel(parcel);
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIAM::UserAuth::UserAuthDriverManagerFuzzTest(data, size);
    return 0;
}
