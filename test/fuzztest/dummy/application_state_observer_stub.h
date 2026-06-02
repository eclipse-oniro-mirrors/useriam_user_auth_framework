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

#ifndef OHOS_ABILITY_RUNTIME_APPLICATION_STATE_OBSERVER_STUB_H
#define OHOS_ABILITY_RUNTIME_APPLICATION_STATE_OBSERVER_STUB_H

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>

#include "iremote_stub.h"
#include "iremote_object.h"
#include "message_parcel.h"
#include "message_option.h"
#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {

enum class ApplicationState {
    APP_STATE_BEGIN = 0,
    APP_STATE_FOREGROUND,
    APP_STATE_BACKGROUND,
    APP_STATE_TERMINATED,
    APP_STATE_END,
};

enum class AppProcessState {
    APP_STATE_BEGIN = 0,
    APP_STATE_READY,
    APP_STATE_RUNNING,
    APP_STATE_SUSPENDED,
    APP_STATE_BACKGROUND,
    APP_STATE_TERMINATED,
    APP_STATE_END,
};

enum class ProcessType {
    NORMAL = 0,
    EXTENSION = 1,
    RENDER = 2,
};

struct AppStateData : public Parcelable {
    bool Marshalling(Parcel &parcel) const override;
    static AppStateData *Unmarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel);

    bool isFocused = false;
    int32_t pid = -1;
    int32_t uid = 0;
    int32_t state = 0;
    std::string bundleName;
};

struct ProcessData : public Parcelable {
    bool Marshalling(Parcel &parcel) const override;
    static ProcessData *Unmarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel);

    std::string bundleName;
    int32_t pid = 0;
    int32_t uid = 0;
    AppProcessState state = AppProcessState::APP_STATE_BEGIN;
    ProcessType processType = ProcessType::NORMAL;
    uint32_t accessTokenId = 0;
};

struct AbilityStateData : public Parcelable {
    bool Marshalling(Parcel &parcel) const override;
    bool MarshallingOne(Parcel &parcel) const;
    static AbilityStateData *Unmarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel);

    int32_t uid = 0;
    int32_t abilityState = 0;
    pid_t pid = 0;
    sptr<IRemoteObject> token;
    std::string bundleName;
    std::string abilityName;
};

struct PageStateData : public Parcelable {
    bool Marshalling(Parcel &parcel) const override;
    static PageStateData *Unmarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel);

    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    std::string pageName;
    int32_t uid = 0;
};

struct PreloadProcessData : public Parcelable {
    bool Marshalling(Parcel &parcel) const override;
    static PreloadProcessData *Unmarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel);

    bool isPreForeground = false;
    pid_t pid = 0;
    int32_t uid = 0;
    std::string bundleName;
};

struct ProcessBindData : public Parcelable {
    bool Marshalling(Parcel &parcel) const override;
    static ProcessBindData *Unmarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel);

    std::string bundleName;
    int32_t pid = 0;
    int32_t uid = 0;
    int32_t bindingRelation = 0;
};

class IApplicationStateObserver : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.IApplicationStateObserver");

    virtual void OnForegroundApplicationChanged(const AppStateData &appStateData) = 0;
    virtual void OnAbilityStateChanged(const AbilityStateData &abilityStateData) = 0;
    virtual void OnExtensionStateChanged(const AbilityStateData &abilityStateData) = 0;
    virtual void OnProcessCreated(const ProcessData &processData) = 0;
    virtual void OnProcessStateChanged(const ProcessData &processData) {}
    virtual void OnWindowShow(const ProcessData &processData) {}
    virtual void OnWindowHidden(const ProcessData &processData) {}
    virtual void OnProcessDied(const ProcessData &processData) = 0;
    virtual void OnApplicationStateChanged(const AppStateData &appStateData) = 0;
    virtual void OnAppStateChanged(const AppStateData &appStateData) {}
    virtual void OnProcessReused(const ProcessData &processData) {}
    virtual void OnAppStarted(const AppStateData &appStateData) {}
    virtual void OnAppStopped(const AppStateData &appStateData) {}
    virtual void OnPageShow(const PageStateData &pageStateData) {}
    virtual void OnPageHide(const PageStateData &pageStateData) {}
    virtual void OnAppCacheStateChanged(const AppStateData &appStateData) {}
    virtual void OnProcessBindingRelationChanged(const ProcessBindData &processBindData) {}
    virtual void OnKeepAliveStateChanged(const ProcessData &processData) {}
    virtual void OnProcessPreForegroundChanged(const PreloadProcessData &preloadProcessData) {}
    virtual void OnProcessTypeChanged(const ProcessData &processData) {}
};

class ApplicationStateObserverStub : public IRemoteStub<IApplicationStateObserver> {
public:
    ApplicationStateObserverStub() = default;
    virtual ~ApplicationStateObserverStub() = default;

    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    void OnForegroundApplicationChanged(const AppStateData &appStateData) override;
    void OnAbilityStateChanged(const AbilityStateData &abilityStateData) override;
    void OnExtensionStateChanged(const AbilityStateData &abilityStateData) override;
    void OnProcessCreated(const ProcessData &processData) override;
    void OnProcessStateChanged(const ProcessData &processData) override;
    void OnWindowShow(const ProcessData &processData) override;
    void OnWindowHidden(const ProcessData &processData) override;
    void OnProcessDied(const ProcessData &processData) override;
    void OnApplicationStateChanged(const AppStateData &appStateData) override;
    void OnAppStateChanged(const AppStateData &appStateData) override;
    void OnProcessReused(const ProcessData &processData) override;
    void OnAppStarted(const AppStateData &appStateData) override;
    void OnAppStopped(const AppStateData &appStateData) override;
    void OnPageShow(const PageStateData &pageStateData) override;
    void OnPageHide(const PageStateData &pageStateData) override;
    void OnAppCacheStateChanged(const AppStateData &appStateData) override;
    void OnProcessBindingRelationChanged(const ProcessBindData &processBindData) override;
    void OnKeepAliveStateChanged(const ProcessData &processData) override;
    void OnProcessPreForegroundChanged(const PreloadProcessData &preloadProcessData) override;
    void OnProcessTypeChanged(const ProcessData &processData) override;

private:
    int32_t HandleOnForegroundApplicationChanged(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnAbilityStateChanged(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnExtensionStateChanged(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnProcessCreated(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnProcessStateChanged(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnWindowShow(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnWindowHidden(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnProcessDied(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnApplicationStateChanged(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnAppStateChanged(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnProcessReused(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnAppStarted(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnAppStopped(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnPageShow(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnPageHide(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnAppCacheStateChanged(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnProcessBindingRelationChanged(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnKeepAliveStateChanged(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnProcessPreForegroundChanged(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnProcessTypeChanged(MessageParcel &data, MessageParcel &reply);

    static std::mutex callbackMutex_;
};

class ApplicationStateObserverRecipient : public IRemoteObject::DeathRecipient {
public:
    using RemoteDiedHandler = std::function<void(const wptr<IRemoteObject> &)>;
    explicit ApplicationStateObserverRecipient(RemoteDiedHandler handler);
    virtual ~ApplicationStateObserverRecipient();
    virtual void OnRemoteDied(const wptr<IRemoteObject> &remote);

private:
    RemoteDiedHandler handler_;
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_APPLICATION_STATE_OBSERVER_STUB_H