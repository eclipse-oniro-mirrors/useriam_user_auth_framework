/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_JS_USER_AUTH_EXTENSION_H
#define OHOS_ABILITY_RUNTIME_JS_USER_AUTH_EXTENSION_H

#include <unordered_set>

#include "configuration.h"
#include "user_auth_extension.h"

class NativeReference;

namespace OHOS {
namespace AbilityRuntime {
class UserAuthExtension;
class JsRuntime;
/**
 * @brief Basic ui extension components.
 */
class JsUserAuthExtension : public UserAuthExtension, public std::enable_shared_from_this<JsUserAuthExtension> {
public:
    explicit JsUserAuthExtension(JsRuntime& jsRuntime);
    virtual ~JsUserAuthExtension() override;

    /**
     * @brief Create JsUserAuthExtension.
     *
     * @param runtime The runtime.
     * @return The JsUserAuthExtension instance.
     */
    static JsUserAuthExtension* Create(const std::unique_ptr<Runtime>& runtime);

    /**
     * @brief Init the ui extension.
     *
     * @param record the ui extension record.
     * @param application the application info.
     * @param handler the ui extension handler.
     * @param token the remote token.
     */
    virtual void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
        const std::shared_ptr<AppExecFwk::OHOSApplication> &application,
        std::shared_ptr<AppExecFwk::AbilityHandler> &handler,
        const sptr<IRemoteObject> &token) override;

    /**
     * @brief Called when this ui extension is started. You must override this function if you want to perform some
     *        initialization operations during ui extension startup.
     *
     * This function can be called only once in the entire lifecycle of an ui extension.
     *
     * @param Want Indicates the {@link Want} structure containing startup information about the ui extension.
     */
    virtual void OnStart(const AAFwk::Want &want) override;

    /**
     * @brief Called when this ui extension is connected for the first time.
     *
     * You can override this function to implement your own processing logic.
     *
     * @param want Indicates the {@link Want} structure containing connection information about the ui extension.
     * @return Returns a pointer to the <b>sid</b> of the connected ui extension.
     */
    virtual sptr<IRemoteObject> OnConnect(const AAFwk::Want &want) override;

    /**
     * @brief Called when all abilities connected to this ui extension are disconnected.
     *
     * You can override this function to implement your own processing logic.
     *
     */
    virtual void OnDisconnect(const AAFwk::Want &want) override;

    /**
     * @brief Called back when ui extension is started.
     *
     * This method can be called only by ui extension. You can use the StartAbility(Want) method to start
     * ui extension. Then the system calls back the current method to use the transferred want parameter to
     * execute its own logic.
     *
     * @param want Indicates the want of ui extension to start.
     * @param restart Indicates the startup mode. The value true indicates that ui extension is restarted after being
     * destroyed, and the value false indicates a normal startup.
     * @param startId Indicates the number of times the ui extension has been started. The startId is incremented
     * by 1 every time the ui extension is started. For example, if the ui extension has been started for six times, the
     * value of startId is 6.
     */
    virtual void OnCommand(const AAFwk::Want &want, bool restart, int startId) override;

    virtual void OnCommandWindow(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo,
        AAFwk::WindowCommand winCmd) override;

    /**
     * @brief Called when this ui extension enters the <b>STATE_STOP</b> state.
     *
     * The ui extension in the <b>STATE_STOP</b> is being destroyed.
     * You can override this function to implement your own processing logic.
     */
    virtual void OnStop() override;

    /**
     * @brief Called when the system configuration is updated.
     *
     * @param configuration Indicates the updated configuration information.
     */
    virtual void OnConfigurationUpdated(const AppExecFwk::Configuration& configuration) override;

    /**
     * @brief Called when this extension enters the <b>STATE_FOREGROUND</b> state.
     *
     *
     * The extension in the <b>STATE_FOREGROUND</b> state is visible.
     * You can override this function to implement your own processing logic.
     */
    virtual void OnForeground(const Want &want, sptr<AAFwk::SessionInfo> sessionInfo) override;

    /**
     * @brief Called when this extension enters the <b>STATE_BACKGROUND</b> state.
     *
     *
     * The extension in the <b>STATE_BACKGROUND</b> state is invisible.
     * You can override this function to implement your own processing logic.
     */
    virtual void OnBackground() override;

    /**
     * @brief Called when ui extension need dump info.
     *
     * @param params The params from ui extension.
     * @param info The dump info to show.
     */
    virtual void Dump(const std::vector<std::string> &params, std::vector<std::string> &info) override;

private:
    virtual void BindContext(napi_env env, napi_value obj);

    napi_value CallObjectMethod(const char *name, const napi_value *argv = nullptr, size_t argc = 0);

    napi_value CallOnConnect(const AAFwk::Want &want);

    napi_value CallOnDisconnect(const AAFwk::Want &want, bool withResult = false);

    void ForegroundWindow(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo);
    void BackgroundWindow(const sptr<AAFwk::SessionInfo> &sessionInfo);
    void DestroyWindow(const sptr<AAFwk::SessionInfo> &sessionInfo);

    JsRuntime& jsRuntime_;
    std::unique_ptr<NativeReference> jsObj_;
    std::shared_ptr<NativeReference> shellContextRef_ = nullptr;
    std::map<uint64_t, sptr<Rosen::Window>> uiWindowMap_;
    std::set<uint64_t> foregroundWindows_;
    std::map<uint64_t, std::shared_ptr<NativeReference>> contentSessions_;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_JS_USER_AUTH_EXTENSION_H
