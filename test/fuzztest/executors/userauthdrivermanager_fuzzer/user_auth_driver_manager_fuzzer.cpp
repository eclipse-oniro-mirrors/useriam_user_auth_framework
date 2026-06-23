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
#include <mutex>

#include "driver_manager.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_executor_iauth_driver_hdi.h"
#include "iam_executor_iauth_executor_hdi.h"

#undef private

#define LOG_TAG "USER_AUTH_EXECUTOR"
#define LOG_FILE_ID LOG_FILE_DRIVER_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
using namespace std;
using namespace OHOS::UserIam::Common;
using namespace OHOS::UserIam::UserAuth;
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

    void SetParcel(const std::shared_ptr<Parcel> &parcel)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fuzzParcel_ = parcel;
    }

private:
    std::mutex mutex_;
    std::shared_ptr<Parcel> fuzzParcel_ {nullptr};
};

auto g_executorHdi = UserIam::Common::MakeShared<DummyAuthExecutorHdi>();

class DummyAuthDriverHdi : public IAuthDriverHdi {
public:
    DummyAuthDriverHdi() = default;
    virtual ~DummyAuthDriverHdi() = default;

    void GetExecutorList(std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> &executorList)
    {
        static const uint32_t maxNum = 20;
        std::lock_guard<std::mutex> lock(mutex_);
        if (fuzzParcel_ == nullptr) {
            return;
        }
        uint32_t num = fuzzParcel_->ReadUint32();
        uint32_t executorNum = num % maxNum;
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

    void OnHdiDisconnect()
    {
        return;
    }

    void SetParcel(const std::shared_ptr<Parcel> &parcel)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fuzzParcel_ = parcel;
    }

private:
    std::mutex mutex_;
    std::shared_ptr<Parcel> fuzzParcel_ {nullptr};
};

auto g_authDriverHdi = UserIam::Common::MakeShared<DummyAuthDriverHdi>();
const std::map<std::string, UserAuth::HdiConfig> GLOBAL_HDI_NAME_TO_CONFIG = {
    {"face_auth_interface_service", {1, g_authDriverHdi}}, {"pin_auth_interface_service", {2, g_authDriverHdi}}};
const string GLOBAL_SERVICE_NAMES[] = {"face_auth_interface_service", "pin_auth_interface_service"};

void FuzzStart(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // driver manager forbids multiple invoke of Start(), it's config must be valid
    Singleton<UserAuth::DriverManager>::GetInstance().Start(GLOBAL_HDI_NAME_TO_CONFIG, true);
    Singleton<UserAuth::DriverManager>::GetInstance().OnFrameworkReady();
    Singleton<UserAuth::DriverManager>::GetInstance().SubscribeHdiDriverStatus();
    std::string serviceName;
    parcel->ReadString(serviceName);
    Singleton<UserAuth::DriverManager>::GetInstance().GetDriverByServiceName(serviceName);
    uint32_t index = parcel->ReadUint32() % (sizeof(GLOBAL_SERVICE_NAMES) / sizeof(GLOBAL_SERVICE_NAMES[0]));
    std::shared_ptr<Driver> driver =
        Singleton<UserAuth::DriverManager>::GetInstance().GetDriverByServiceName(GLOBAL_SERVICE_NAMES[index]);
    // Since config is valid, GetDriverByServiceName should never return null.
    // If it happens to be null, let fuzz process crash.
    driver->OnHdiConnect();
    driver->OnHdiDisconnect();
    Singleton<UserAuth::DriverManager>::GetInstance().OnAllHdiDisconnect();
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzStart);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzStart,
};

void UserAuthDriverManagerFuzzTest(const uint8_t *data, size_t size)
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
    g_authDriverHdi->SetParcel(parcel);
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
    OHOS::UserIam::UserAuth::UserAuthDriverManagerFuzzTest(data, size);
    return 0;
}
