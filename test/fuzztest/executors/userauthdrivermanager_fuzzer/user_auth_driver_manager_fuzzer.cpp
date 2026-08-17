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

#include "device_manager_listener.h"
#include "driver.h"
#include "driver_manager.h"
#include "framework_ready_listener.h"
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

    void GetExecutorList(std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> &executorList) override
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

    void OnHdiDisconnect() override
    {
        return;
    }

    void OnFrameworkDown() override
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

std::shared_ptr<Driver> CreateDriver(std::shared_ptr<Parcel> parcel)
{
    std::string serviceName = "fuzz_driver_service";
    HdiConfig config = {};
    uint32_t id = parcel->ReadUint32();
    config.id = static_cast<uint16_t>(id);
    bool useNullDriver = parcel->ReadBool();
    if (useNullDriver) {
        config.driver = nullptr;
    } else {
        config.driver = g_authDriverHdi;
    }
    return MakeShared<Driver>(serviceName, config);
}

void FuzzStart(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    Singleton<UserAuth::DriverManager>::GetInstance().Start(GLOBAL_HDI_NAME_TO_CONFIG, true);
    IAM_LOGI("end");
}

void FuzzDriverOnHdiConnect(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    auto driver = CreateDriver(parcel);
    if (driver == nullptr) {
        return;
    }
    driver->OnHdiConnect();
    IAM_LOGI("end");
}

void FuzzDriverOnHdiDisconnect(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    auto driver = CreateDriver(parcel);
    if (driver == nullptr) {
        return;
    }
    driver->OnHdiConnect();
    driver->OnHdiDisconnect();
    IAM_LOGI("end");
}

void FuzzDriverOnFrameworkReady(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    auto driver = CreateDriver(parcel);
    if (driver == nullptr) {
        return;
    }
    driver->OnHdiConnect();
    driver->OnFrameworkReady();
    IAM_LOGI("end");
}

void FuzzDriverOnFrameworkDown(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    auto driver = CreateDriver(parcel);
    if (driver == nullptr) {
        return;
    }
    driver->OnFrameworkReady();
    driver->OnFrameworkDown();
    IAM_LOGI("end");
}

void FuzzDriverConnectThenReady(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    auto driver = CreateDriver(parcel);
    if (driver == nullptr) {
        return;
    }
    driver->OnHdiConnect();
    driver->OnFrameworkReady();
    driver->OnFrameworkDown();
    driver->OnHdiDisconnect();
    IAM_LOGI("end");
}

void FuzzDriverReadyThenConnect(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    auto driver = CreateDriver(parcel);
    if (driver == nullptr) {
        return;
    }
    driver->OnFrameworkReady();
    driver->OnHdiConnect();
    IAM_LOGI("end");
}

void FuzzDriverRepeatedCallbacks(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    auto driver = CreateDriver(parcel);
    if (driver == nullptr) {
        return;
    }
    driver->OnHdiConnect();
    driver->OnHdiConnect();
    driver->OnFrameworkReady();
    driver->OnFrameworkReady();
    driver->OnFrameworkDown();
    driver->OnFrameworkDown();
    driver->OnHdiDisconnect();
    driver->OnHdiDisconnect();
    IAM_LOGI("end");
}

void FuzzDriverInit(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    auto driver = CreateDriver(parcel);
    if (driver == nullptr) {
        return;
    }
    driver->Init();
    IAM_LOGI("end");
}

void FuzzDriverInitAndCallbacks(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    auto driver = CreateDriver(parcel);
    if (driver == nullptr) {
        return;
    }
    driver->Init();
    driver->OnHdiConnect();
    driver->OnFrameworkReady();
    driver->OnFrameworkDown();
    driver->OnHdiDisconnect();
    IAM_LOGI("end");
}

void FuzzDeviceManagerListenerSubscribe(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    auto listener = MakeShared<DeviceManagerListener>(
        "fuzz_service",
        []() {},
        []() {});
    if (listener == nullptr) {
        return;
    }
    listener->Subscribe();
    IAM_LOGI("end");
}

void FuzzFrameworkReadyListenerSubscribe(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    auto listener = std::make_shared<FrameworkReadyListener>(
        []() {},
        []() {});
    if (listener == nullptr) {
        return;
    }
    listener->Subscribe();
    listener->EnsureRegisterExecutors();
    listener->StopTimer();
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzStart);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzStart,
    FuzzDriverOnHdiConnect,
    FuzzDriverOnHdiDisconnect,
    FuzzDriverOnFrameworkReady,
    FuzzDriverOnFrameworkDown,
    FuzzDriverConnectThenReady,
    FuzzDriverReadyThenConnect,
    FuzzDriverRepeatedCallbacks,
    FuzzDriverInit,
    FuzzDriverInitAndCallbacks,
    FuzzDeviceManagerListenerSubscribe,
    FuzzFrameworkReadyListenerSubscribe,
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
    uint32_t index = parcel->ReadUint32() % (sizeof(g_fuzzFuncs) / sizeof(FuzzFunc *));
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
