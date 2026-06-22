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

#include "soft_bus_manager.h"

#include <cinttypes>
#include <string>
#include <thread>
#include "socket.h"

#include "device_state_listener.h"
#include "device_manager.h"
#include "iam_logger.h"
#include "iservice_registry.h"
#include "remote_connect_listener_manager.h"
#include "socket_factory.h"
#include "soft_bus_base_socket.h"
#include "softbus_error_code.h"
#include "soft_bus_socket_listener.h"
#include "system_ability_definition.h"
#include "thread_handler.h"
#include "thread_handler_manager.h"
#include "token_setproc.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_SOFT_BUS_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS::DistributedHardware;
static const std::string USER_AUTH_SOCKET_NAME = "ohos.useriam.";
static constexpr uint32_t SOCKET_NAME_MAX_LEN = 256;
static constexpr uint32_t PACKAGE_NAME_MAX_LEN = 256;

static constexpr uint32_t QOS_LEN = 3;
static constexpr int32_t MIN_BW = 1024 * 1024; // 1M
static constexpr int32_t MAX_LATENCY = 30 * 1000; // 30s
static constexpr int32_t MIN_LATENCY = 100; // 100ms
static constexpr int32_t MAX_TIMEOUT = 3 * 60 * 1000; // 3min

static constexpr int32_t BIND_SERVICE_MAX_RETRY_TIMES = 3;
static constexpr int32_t BIND_SERVICE_SLEEP_TIMES_MS = 100; // 0.1s

static const int32_t MAX_ONBYTES_RECEIVED_DATA_LEN = 1024 * 1024 * 10;

SoftBusManager::SoftBusManager()
{
    IAM_LOGD("start.");
}

SoftBusManager::~SoftBusManager()
{
    IAM_LOGD("start.");
    Stop();
}

SoftBusManager &SoftBusManager::GetInstance()
{
    IAM_LOGD("start.");
    static SoftBusManager instance;
    return instance;
}

void SoftBusManager::Start()
{
    IAM_LOGD("start.");
    std::unique_lock<std::recursive_mutex> lock(mutex_);
    if (inited_) {
        IAM_LOGI("already initialized, skip");
        return;
    }
    ResultCode ret = RegistDeviceManagerListener();
    if (ret != SUCCESS) {
        IAM_LOGE("RegistDeviceManagerListener fail");
        return;
    }
    ret = RegistSoftBusListener();
    if (ret != SUCCESS) {
        IAM_LOGE("RegistSoftBusListener fail");
        return;
    }
    inited_ = true;
}

void SoftBusManager::Stop()
{
    IAM_LOGD("start.");
    std::unique_lock<std::recursive_mutex> lock(mutex_);
    if (!inited_) {
        IAM_LOGI("not inited, skip");
        return;
    }
    ResultCode ret = UnRegistDeviceManagerListener();
    if (ret != SUCCESS) {
        IAM_LOGE("UnRegistDeviceManagerListener fail");
        return;
    }
    ret = UnRegistSoftBusListener();
    if (ret != SUCCESS) {
        IAM_LOGE("UnRegistSoftBusListener fail");
        return;
    }
    inited_ = false;
}

ResultCode SoftBusManager::RegistDeviceManagerListener()
{
    IAM_LOGD("start.");
    std::lock_guard<std::recursive_mutex> lock(deviceManagerMutex_);
    if (deviceManagerServiceListener_ != nullptr) {
        IAM_LOGI("deviceManagerServiceListener_ is not nullptr.");
        return SUCCESS;
    }

#ifndef IAM_TEST_ENABLE
    deviceManagerServiceListener_ = SystemAbilityListener::Subscribe(
        "device_manager", DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID,
        []() {
            SoftBusManager::GetInstance().DeviceInit();
        },
        []() {
            SoftBusManager::GetInstance().DeviceUnInit();
        });
    if (deviceManagerServiceListener_ == nullptr) {
        IAM_LOGE("deviceManagerServiceListener_ is nullptr.");
        return GENERAL_ERROR;
    }
#endif
    IAM_LOGI("RegistDeviceManagerListener success.");
    return SUCCESS;
}

ResultCode SoftBusManager::UnRegistDeviceManagerListener()
{
    IAM_LOGD("start.");
    std::lock_guard<std::recursive_mutex> lock(deviceManagerMutex_);
    if (deviceManagerServiceListener_ == nullptr) {
        IAM_LOGI("deviceManagerServiceListener_ is nullptr.");
        return SUCCESS;
    }

    int32_t ret = SystemAbilityListener::UnSubscribe(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID,
        deviceManagerServiceListener_);
    if (ret != SUCCESS) {
        IAM_LOGE("UnSubscribe service fail.");
        return GENERAL_ERROR;
    }

    deviceManagerServiceListener_ = nullptr;
    IAM_LOGI("UnRegistDeviceManagerListener success.");
    return SUCCESS;
}

ResultCode SoftBusManager::RegistSoftBusListener()
{
    IAM_LOGD("start.");
    std::lock_guard<std::recursive_mutex> lock(softBusMutex_);
    if (softBusServiceListener_ != nullptr) {
        IAM_LOGI("softBusServiceListener_ is not nullptr.");
        return SUCCESS;
    }

    softBusServiceListener_ = SystemAbilityListener::Subscribe(
        "softbus_server", SOFTBUS_SERVER_SA_ID,
        []() {
            SoftBusManager::GetInstance().ServiceSocketInit();
        },
        []() {
            SoftBusManager::GetInstance().ServiceSocketUnInit();
        });
    if (softBusServiceListener_ == nullptr) {
        IAM_LOGE("softBusServiceListener_ is nullptr.");
        return GENERAL_ERROR;
    }

    IAM_LOGI("RegistSoftBusListener success.");
    return SUCCESS;
}

ResultCode SoftBusManager::UnRegistSoftBusListener()
{
    IAM_LOGD("start.");
    std::lock_guard<std::recursive_mutex> lock(softBusMutex_);
    if (softBusServiceListener_ == nullptr) {
        IAM_LOGI("softBusServiceListener_ is nullptr.");
        return SUCCESS;
    }

    int32_t ret = SystemAbilityListener::UnSubscribe(SOFTBUS_SERVER_SA_ID, softBusServiceListener_);
    if (ret != SUCCESS) {
        IAM_LOGE("UnSubscribe service fail.");
        return GENERAL_ERROR;
    }

    softBusServiceListener_ = nullptr;
    IAM_LOGI("UnRegistSoftBusListener success.");
    return SUCCESS;
}

ResultCode SoftBusManager::DeviceInit()
{
    IAM_LOGD("start.");
    auto dmInitCallback = Common::MakeShared<IamDmInitCallback>();
    if (dmInitCallback == nullptr) {
        IAM_LOGE("dmInitCallback create fail");
        return GENERAL_ERROR;
    }

    int ret = DeviceManager::GetInstance().InitDeviceManager(USER_AUTH_PACKAGE_NAME, dmInitCallback);
    if (ret != SUCCESS) {
        IAM_LOGE("Initialize: InitDeviceManager error, result: %{public}d", ret);
        return GENERAL_ERROR;
    }

    return SUCCESS;
}

void SoftBusManager::DeviceUnInit()
{
    IAM_LOGD("start.");
    int32_t ret = DeviceManager::GetInstance().UnInitDeviceManager(USER_AUTH_PACKAGE_NAME);
    if (ret != SUCCESS) {
        IAM_LOGE("UnInitDeviceManager failed, code: %{public}d", ret);
    }

    IAM_LOGI("DeviceUnInit success");
}

ResultCode SoftBusManager::ServiceSocketListen(const int32_t socketId)
{
    IAM_LOGD("start.");
    QosTV serverQos[] = {
        { .qos = QOS_TYPE_MIN_BW,      .value = MIN_BW },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = MAX_LATENCY },
        { .qos = QOS_TYPE_MIN_LATENCY, .value = MIN_LATENCY },
        { .qos = QOS_TYPE_MAX_WAIT_TIMEOUT, .value = MAX_TIMEOUT },
    };

    ISocketListener listener;
    listener.OnBind = SoftBusSocketListener::OnBind;
    listener.OnShutdown = SoftBusSocketListener::OnShutdown;
    listener.OnBytes = SoftBusSocketListener::OnClientBytes;
    listener.OnNegotiate = SoftBusSocketListener::OnNegotiate;

    int32_t ret = Listen(socketId, serverQos, QOS_LEN, &listener);
    if (ret != SUCCESS) {
        IAM_LOGE("create listener failed, ret is %{public}d.", ret);
        return GENERAL_ERROR;
    }

    IAM_LOGI("ServiceSocketListen success.");
    return SUCCESS;
}

void SoftBusManager::ServiceSocketInit()
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    IF_FALSE_LOGE_AND_RETURN(handler != nullptr);
    handler->PostTask([=]() {
        ResultCode ret = GENERAL_ERROR;
        auto sleepTime = std::chrono::milliseconds(BIND_SERVICE_SLEEP_TIMES_MS);
        for (int32_t retryTimes = 0; retryTimes < BIND_SERVICE_MAX_RETRY_TIMES; retryTimes++) {
            ret = DoServiceSocketInit();
            if (ret == SUCCESS) {
                break;
            }
            std::this_thread::sleep_for(sleepTime);
        }

        IAM_LOGI("ServiceSocketInit result %{public}d.", ret);
    });
}

ResultCode SoftBusManager::DoServiceSocketInit()
{
    IAM_LOGD("start.");
    std::string serviceName = USER_AUTH_SOCKET_NAME + "service";
    char name[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(name, SOCKET_NAME_MAX_LEN, serviceName)) {
        IAM_LOGE("copy socket name fail");
        return GENERAL_ERROR;
    }

    char pkgName[PACKAGE_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(pkgName, PACKAGE_NAME_MAX_LEN, USER_AUTH_PACKAGE_NAME)) {
        IAM_LOGE("copy pkg name fail");
        return GENERAL_ERROR;
    }

    SocketInfo info = {
        .name = name,
        .pkgName = pkgName,
        .dataType = DATA_TYPE_BYTES
    };
    int32_t socketId = Socket(info);
    if (socketId <= INVALID_SOCKET_ID) {
        IAM_LOGE("create service socket failed.");
        return GENERAL_ERROR;
    }

    int ret = ServiceSocketListen(socketId);
    if (ret != SUCCESS) {
        IAM_LOGE("socket listen failed, ret is %{public}d.", ret);
        return GENERAL_ERROR;
    }

    auto serverSocket = SocketFactory::CreateServerSocket(socketId);
    if (serverSocket == nullptr) {
        IAM_LOGE("server socket create failed.");
        return GENERAL_ERROR;
    }

    AddSocket(socketId, serverSocket);
    SetServerSocket(serverSocket);
    IAM_LOGI("ServiceSocketInit success.");
    return SUCCESS;
}

void SoftBusManager::ServiceSocketUnInit()
{
    IAM_LOGE("soft bus service is down.");
    auto serverSocket = GetServerSocket();
    if (serverSocket == nullptr) {
        IAM_LOGI("serverSocket is nullptr.");
        return;
    }
    DeleteSocket(serverSocket->GetSocketId());
    ClearServerSocket();

    std::vector<int32_t> socketIds;
    {
        std::lock_guard<std::recursive_mutex> lock(socketMutex_);
        socketIds.reserve(socketMap_.size());
        for (const auto &iter : socketMap_) {
            socketIds.push_back(iter.first);
        }
    }
    for (int32_t socketId : socketIds) {
        IAM_LOGI("service down shutdown socket %{public}d", socketId);
        OnShutdown(socketId, SHUTDOWN_REASON_SERVICE_DIED);
    }

    IAM_LOGI("UnInitialize success");
}

int32_t SoftBusManager::ClientSocketInit(const std::string &connectionName, const std::string &networkId)
{
    IAM_LOGD("start.");
    std::string clientName = USER_AUTH_SOCKET_NAME + connectionName;
    char name[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(name, SOCKET_NAME_MAX_LEN, clientName)) {
        IAM_LOGE("copy socket name fail");
        return INVALID_SOCKET_ID;
    }

    std::string serviceName = USER_AUTH_SOCKET_NAME + "service";
    char peerName[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(peerName, SOCKET_NAME_MAX_LEN, serviceName)) {
        IAM_LOGE("copy peer name fail");
        return INVALID_SOCKET_ID;
    }

    char peerNetworkId[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(peerNetworkId, SOCKET_NAME_MAX_LEN, networkId)) {
        IAM_LOGE("copy peer networkId name fail");
        return INVALID_SOCKET_ID;
    }

    char pkgName[PACKAGE_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(pkgName, PACKAGE_NAME_MAX_LEN, USER_AUTH_PACKAGE_NAME)) {
        IAM_LOGE("copy pkg name fail");
        return INVALID_SOCKET_ID;
    }

    SocketInfo info = {
        .name = name,
        .peerName = peerName,
        .peerNetworkId = peerNetworkId,
        .pkgName = pkgName,
        .dataType = DATA_TYPE_BYTES
    };

    return Socket(info);
}

ResultCode SoftBusManager::ClientSocketBind(const int32_t socketId)
{
    IAM_LOGD("start.");
    QosTV clientQos[] = {
        { .qos = QOS_TYPE_MIN_BW,      .value = MIN_BW },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = MAX_LATENCY },
        { .qos = QOS_TYPE_MIN_LATENCY, .value = MIN_LATENCY },
    };

    ISocketListener listener;
    listener.OnShutdown = SoftBusSocketListener::OnShutdown;
    listener.OnBytes = SoftBusSocketListener::OnServerBytes;
    listener.OnQos = SoftBusSocketListener::OnQos;

    int32_t ret = SOFTBUS_INVALID_PARAM;
    auto sleepTime = std::chrono::milliseconds(BIND_SERVICE_SLEEP_TIMES_MS);
    for (int32_t retryTimes = 0; retryTimes < BIND_SERVICE_MAX_RETRY_TIMES; retryTimes++) {
        ret = Bind(socketId, clientQos, QOS_LEN, &listener);
        if (ret == SOFTBUS_OK) {
            break;
        }
        std::this_thread::sleep_for(sleepTime);
    }

    if (ret != SOFTBUS_OK) {
        IAM_LOGE("ClientSocketBind fail.");
        return GENERAL_ERROR;
    }
    IAM_LOGI("ClientSocketBind success.");
    return SUCCESS;
}

ResultCode SoftBusManager::DoOpenConnectionInner(const std::string &connectionName, const uint32_t tokenId,
    const std::string &networkId, RemoteConnectOpenTrace &trace)
{
    trace.connectionName = connectionName;
    trace.networkId = networkId;
    int32_t ret = SetFirstCallerTokenID(tokenId);
    if (ret != SUCCESS) {
        IAM_LOGE("SetFirstCallerTokenID fail");
    }

    int32_t socketId = ClientSocketInit(connectionName, networkId);
    if (socketId <= INVALID_SOCKET_ID) {
        IAM_LOGE("create client socket failed.");
        return GENERAL_ERROR;
    }
    trace.socketId = socketId;

    auto clientSocket = SocketFactory::CreateClientSocket(socketId, connectionName, networkId);
    if (clientSocket == nullptr) {
        IAM_LOGE("CreateClientSocket failed, connectionName:%{public}s", connectionName.c_str());
        return GENERAL_ERROR;
    }

    ret = ClientSocketBind(socketId);
    if (ret != SUCCESS) {
        IAM_LOGE("client socket bind service fail");
        return GENERAL_ERROR;
    }

    AddConnection(connectionName, clientSocket);
    AddSocket(socketId, clientSocket);
    IAM_LOGI("Bind service success, connectionName:%{public}s socketId:%{public}d.", connectionName.c_str(), socketId);
    return SUCCESS;
}

void SoftBusManager::DoOpenConnection(const std::string &connectionName, const uint32_t tokenId,
    const std::string &networkId)
{
    IAM_LOGI("open connection %{public}s start.", connectionName.c_str());
    RemoteConnectOpenTrace trace = {};
    auto beginTime = std::chrono::steady_clock::now();
    ResultCode result = DoOpenConnectionInner(connectionName, tokenId, networkId, trace);
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - beginTime);
    IAM_LOGI("connection %{public}s OpenConnectionDuration %{public}" PRIu64 " ms", connectionName.c_str(),
        static_cast<uint64_t>(duration.count()));
    trace.timeSpan = static_cast<uint64_t>(duration.count());
    trace.operationResult = result;
    ReportRemoteConnectOpen(trace);

    if (result != SUCCESS) {
        RemoteConnectListenerManager::GetInstance().OnConnectionDown(connectionName);
        IAM_LOGE("open connection %{public}s fail", connectionName.c_str());
        return;
    }

    RemoteConnectListenerManager::GetInstance().OnConnectionUp(connectionName);
    IAM_LOGI("open connection %{public}s success.", connectionName.c_str());
}

ResultCode SoftBusManager::OpenConnection(const std::string &connectionName, const uint32_t tokenId,
    const std::string &networkId)
{
    IAM_LOGD("start.");

    ThreadHandlerManager::GetInstance().PostTask(connectionName, [=]() {
        DoOpenConnection(connectionName, tokenId, networkId);
    });

    IAM_LOGI("Open connection %{public}s task added.", connectionName.c_str());
    return SUCCESS;
}

ResultCode SoftBusManager::DoCloseConnection(const std::string &connectionName)
{
    IAM_LOGI("close connection %{public}s start.", connectionName.c_str());
    std::shared_ptr<BaseSocket> clientSocket = FindClientSocket(connectionName);
    if (clientSocket == nullptr) {
        IAM_LOGE("clientSocket is nullptr");
        return GENERAL_ERROR;
    }

    int32_t socketId = clientSocket->GetSocketId();
    if (socketId == INVALID_SOCKET_ID) {
        IAM_LOGE("socket id is invalid");
        return GENERAL_ERROR;
    }

    RemoteConnectListenerManager::GetInstance().OnConnectionDown(connectionName);
    DeleteSocket(socketId);
    DeleteConnection(connectionName);
    IAM_LOGI("close connection %{public}s socketId %{public}d success", connectionName.c_str(), socketId);
    return SUCCESS;
}

ResultCode SoftBusManager::CloseConnection(const std::string &connectionName)
{
    IAM_LOGD("start.");

    ThreadHandlerManager::GetInstance().PostTask(connectionName, [=]() {
        DoCloseConnection(connectionName);
    });

    IAM_LOGI("Close connection %{public}s task added.", connectionName.c_str());
    return SUCCESS;
}

ResultCode SoftBusManager::SendMessage(const std::string &connectionName,
    const std::string &srcEndPoint, const std::string &destEndPoint,
    const std::shared_ptr<Attributes> &attributes, MsgCallback &callback)
{
    IAM_LOGD("start.");
    IF_FALSE_LOGE_AND_RETURN_VAL(attributes != nullptr, INVALID_PARAMETERS);

    ResultCode ret = SUCCESS;
    auto serverSocket = GetServerSocket();
    IF_FALSE_LOGE_AND_RETURN_VAL(serverSocket != nullptr, GENERAL_ERROR);

    ret = serverSocket->SendMessage(connectionName, srcEndPoint, destEndPoint, attributes, callback);
    if (ret == SUCCESS) {
        IAM_LOGI("SendMessage success");
        return SUCCESS;
    }
    IAM_LOGI("try to send message using serverSocket fail, ret:%{public}d", ret);

    std::shared_ptr<BaseSocket> clientSocket = FindClientSocket(connectionName);
    if (clientSocket == nullptr) {
        IAM_LOGE("failed to find clientSocket");
        return GENERAL_ERROR;
    }

    ret = clientSocket->SendMessage(connectionName, srcEndPoint, destEndPoint, attributes, callback);
    if (ret != SUCCESS) {
        IAM_LOGE("clientSocket send message fail, ret:%{public}d", ret);
        return GENERAL_ERROR;
    }

    IAM_LOGI("SendMessage success.");
    return SUCCESS;
}

void SoftBusManager::OnBind(int32_t socketId, PeerSocketInfo info)
{
    IAM_LOGI("socket id is %{public}d.", socketId);
    if (socketId <= INVALID_SOCKET_ID) {
        IAM_LOGE("socket id invalid.");
        return;
    }

    auto serverSocket = GetServerSocket();
    if (serverSocket == nullptr) {
        IAM_LOGE("serverSocket is nullptr.");
        return;
    }

    serverSocket->OnBind(socketId, info);
}

void SoftBusManager::OnShutdown(int32_t socketId, ShutdownReason reason)
{
    IAM_LOGI("socket id %{public}d shutdown because %{public}d.", socketId, reason);
    if (socketId <= INVALID_SOCKET_ID) {
        IAM_LOGE("socket id invalid.");
        return;
    }

    auto serverSocket = GetServerSocket();
    if (serverSocket != nullptr) {
        serverSocket->OnShutdown(socketId, reason);
        RemoteConnectFaultTrace serverSocketTrace = serverSocket->GetCurrTraceInfo();
        serverSocketTrace.reason = "Shutdown:" + std::to_string(reason);
        ReportConnectFaultTrace(serverSocketTrace);
    }

    auto clientSocket = FindSocketBySocketId(socketId);
    if (clientSocket == nullptr) {
        IAM_LOGI("clientSocket is nullptr.");
        return;
    }
    clientSocket->OnShutdown(socketId, reason);
    DeleteSocket(socketId);
    DeleteConnection(clientSocket->GetConnectionName());
    RemoteConnectFaultTrace clientSocketTrace = clientSocket->GetCurrTraceInfo();
    clientSocketTrace.reason = "Shutdown:" + std::to_string(reason);
    ReportConnectFaultTrace(clientSocketTrace);
    IAM_LOGI("shutdown socket id %{public}d success.", socketId);
}

void SoftBusManager::OnClientBytes(int32_t socketId, const void *data, uint32_t dataLen)
{
    IAM_LOGI("socket fd %{public}d, recv len %{public}u.", socketId, dataLen);
    if ((socketId <= INVALID_SOCKET_ID) || (data == nullptr) ||
        (dataLen == 0) || (dataLen > MAX_ONBYTES_RECEIVED_DATA_LEN)) {
        IAM_LOGE("params invalid.");
        return;
    }

    auto serverSocket = GetServerSocket();
    if (serverSocket == nullptr) {
        IAM_LOGE("serverSocket is nullptr.");
        return;
    }

    serverSocket->OnBytes(socketId, data, dataLen);
}

void SoftBusManager::OnServerBytes(int32_t socketId, const void *data, uint32_t dataLen)
{
    IAM_LOGI("socket fd %{public}d, recv len %{public}u.", socketId, dataLen);
    if ((socketId <= INVALID_SOCKET_ID) || (data == nullptr) ||
        (dataLen == 0) || (dataLen > MAX_ONBYTES_RECEIVED_DATA_LEN)) {
        IAM_LOGE("params invalid.");
        return;
    }

    auto clientSocket = FindSocketBySocketId(socketId);
    if (clientSocket == nullptr) {
        IAM_LOGE("clientSocket is nullptr.");
        return;
    }

    clientSocket->OnBytes(socketId, data, dataLen);
}

void SoftBusManager::AddSocket(const int32_t socketId, std::shared_ptr<BaseSocket> &socket)
{
    IAM_LOGD("start.");
    IF_FALSE_LOGE_AND_RETURN(socket != nullptr);
    IF_FALSE_LOGE_AND_RETURN(socketId != INVALID_SOCKET_ID);

    std::lock_guard<std::recursive_mutex> lock(socketMutex_);
    socketMap_.insert(std::pair<int32_t, std::shared_ptr<BaseSocket>>(socketId, socket));
}

void SoftBusManager::DeleteSocket(const int32_t socketId)
{
    IAM_LOGD("start.");
    IF_FALSE_LOGE_AND_RETURN(socketId != INVALID_SOCKET_ID);

    std::lock_guard<std::recursive_mutex> lock(socketMutex_);
    auto iter = socketMap_.find(socketId);
    if (iter == socketMap_.end()) {
        IAM_LOGE("socketId:%{public}d not found.", socketId);
        return;
    }
    socketMap_.erase(socketId);
}

std::shared_ptr<BaseSocket> SoftBusManager::FindSocketBySocketId(const int32_t socketId)
{
    IAM_LOGD("start.");
    IF_FALSE_LOGE_AND_RETURN_VAL(socketId != INVALID_SOCKET_ID, nullptr);

    std::lock_guard<std::recursive_mutex> lock(socketMutex_);
    std::shared_ptr<BaseSocket> socket = nullptr;
    auto iter = socketMap_.find(socketId);
    if (iter != socketMap_.end()) {
        socket = iter->second;
    }
    return socket;
}

bool SoftBusManager::CheckAndCopyStr(char *dest, uint32_t destLen, const std::string &src)
{
    if (destLen < src.length() + 1) {
        IAM_LOGE("Invalid src length");
        return false;
    }
    if (strcpy_s(dest, destLen, src.c_str()) != EOK) {
        IAM_LOGE("Invalid src");
        return false;
    }
    return true;
}

void SoftBusManager::SetServerSocket(std::shared_ptr<BaseSocket> &socket)
{
    IAM_LOGD("start.");
    IF_FALSE_LOGE_AND_RETURN(socket != nullptr);
    std::lock_guard<std::recursive_mutex> lock(ServerSocketMutex_);
    serverSocket_ = socket;
}

void SoftBusManager::ClearServerSocket()
{
    IAM_LOGD("start.");
    std::lock_guard<std::recursive_mutex> lock(ServerSocketMutex_);
    serverSocket_ = nullptr;
}

void SoftBusManager::AddConnection(const std::string &connectionName, std::shared_ptr<BaseSocket> &socket)
{
    IAM_LOGD("start.");
    IF_FALSE_LOGE_AND_RETURN(socket != nullptr);

    std::lock_guard<std::recursive_mutex> lock(connectionMutex_);
    clientSocketMap_.insert(std::pair<std::string, std::shared_ptr<BaseSocket>>(connectionName, socket));
}

void SoftBusManager::DeleteConnection(const std::string &connectionName)
{
    IAM_LOGD("start.");
    std::lock_guard<std::recursive_mutex> lock(connectionMutex_);
    auto iter = clientSocketMap_.find(connectionName);
    if (iter == clientSocketMap_.end()) {
        IAM_LOGE("connectionName:%{public}s not found.", connectionName.c_str());
        return;
    }
    clientSocketMap_.erase(connectionName);
}

std::shared_ptr<BaseSocket> SoftBusManager::FindClientSocket(const std::string &connectionName)
{
    IAM_LOGD("start.");
    std::lock_guard<std::recursive_mutex> lock(connectionMutex_);
    std::shared_ptr<BaseSocket> clientSocket = nullptr;
    auto iter = clientSocketMap_.find(connectionName);
    if (iter != clientSocketMap_.end()) {
        clientSocket = iter->second;
    }
    return clientSocket;
}

std::shared_ptr<BaseSocket> SoftBusManager::GetServerSocket()
{
    std::lock_guard<std::recursive_mutex> lock(ServerSocketMutex_);
    return serverSocket_;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS