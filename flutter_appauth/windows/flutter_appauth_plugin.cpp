#define WEBVIEW_EDGE
#include "include/flutter_appauth/flutter_appauth_plugin.h"

// This must be included before many other Windows headers.
#include <windows.h>
#include <tchar.h>

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>

#include <map>
#include <memory>
#include <sstream>

#include "webview/webview.hpp"

namespace
{
  struct TokenRequestParameters
  {
    std::string clientId;
    std::string clientSecret;
    std::string issuer;
    std::string grantType;
    std::string discoveryUrl;
    std::string redirectUrl;
    std::string refreshToken;
    std::string codeVerifier;
    std::string authorizationCode;
    flutter::EncodableList scopes;
    flutter::EncodableMap serviceConfigurationParameters;
    flutter::EncodableMap additionalParameters;
    bool preferEphemeralSession = false;

  public:
    void parse(const flutter::EncodableValue *args)
    {
      const auto *arguments = std::get_if<flutter::EncodableMap>(args);
      if (arguments)
        processArguments(arguments);
    }

  protected:
    virtual void processArguments(const flutter::EncodableMap *arguments)
    {
      const auto ci = arguments->find(flutter::EncodableValue("clientId"));
      if (ci != arguments->end() && !ci->second.IsNull())
        clientId = std::get<std::string>(ci->second);

      const auto cs = arguments->find(flutter::EncodableValue("clientSecret"));
      if (cs != arguments->end() && !cs->second.IsNull())
        clientSecret = std::get<std::string>(cs->second);

      const auto is = arguments->find(flutter::EncodableValue("issuer"));
      if (is != arguments->end() && !is->second.IsNull())
        issuer = std::get<std::string>(is->second);

      const auto di = arguments->find(flutter::EncodableValue("discoveryUrl"));
      if (di != arguments->end() && !di->second.IsNull())
        discoveryUrl = std::get<std::string>(di->second);

      const auto ru = arguments->find(flutter::EncodableValue("redirectUrl"));
      if (ru != arguments->end() && !ru->second.IsNull())
        redirectUrl = std::get<std::string>(ru->second);

      const auto rt = arguments->find(flutter::EncodableValue("refreshToken"));
      if (rt != arguments->end() && !rt->second.IsNull())
        refreshToken = std::get<std::string>(rt->second);

      const auto ac = arguments->find(flutter::EncodableValue("authorizationCode"));
      if (ac != arguments->end() && !ac->second.IsNull())
        authorizationCode = std::get<std::string>(ac->second);

      const auto cv = arguments->find(flutter::EncodableValue("codeVerifier"));
      if (cv != arguments->end() && !cv->second.IsNull())
        codeVerifier = std::get<std::string>(cv->second);

      const auto gt = arguments->find(flutter::EncodableValue("grantType"));
      if (gt != arguments->end() && !gt->second.IsNull())
        grantType = std::get<std::string>(gt->second);

      const auto sc = arguments->find(flutter::EncodableValue("scopes"));
      if (sc != arguments->end() && !sc->second.IsNull())
      {
        // const auto mapp = std::get<flutter::EncodableList>(sc->second);
        scopes = std::get<flutter::EncodableList>(sc->second);
        // const auto *mapp = std::get_if<flutter::EncodableMap>(sc->second);
        //scopes = std::get<std::vector<std::string>>(sc->second);
      }

      const auto scf = arguments->find(flutter::EncodableValue("serviceConfiguration"));
      if (scf != arguments->end() && !scf->second.IsNull())
      {
        serviceConfigurationParameters = std::get<flutter::EncodableMap>(scf->second);
      }

      const auto ap = arguments->find(flutter::EncodableValue("additionalParameters"));
      if (ap != arguments->end() && !ap->second.IsNull())
      {
        additionalParameters = std::get<flutter::EncodableMap>(ap->second);
      }

      const auto pes = arguments->find(flutter::EncodableValue("preferEphemeralSession"));
      if (pes != arguments->end() && !pes->second.IsNull())
      {
        preferEphemeralSession = std::get<bool>(pes->second);
      }
    }
  };

  struct AuthorizationTokenRequestParameters : public TokenRequestParameters
  {
    std::string loginHint;
    flutter::EncodableList promptValues;

  protected:
    void processArguments(const flutter::EncodableMap *arguments) override
    {
      TokenRequestParameters::processArguments(arguments);

      const auto lh = arguments->find(flutter::EncodableValue("loginHint"));
      if (lh != arguments->end() && !lh->second.IsNull())
        loginHint = std::get<std::string>(lh->second);

      const auto pv = arguments->find(flutter::EncodableValue("promptValues"));
      if (pv != arguments->end() && !pv->second.IsNull())
        promptValues = std::get<flutter::EncodableList>(pv->second);
    };
  };

  class FlutterAppauthPlugin : public flutter::Plugin
  {
  private:
    // The registrar for this plugin, for accessing the window.
    flutter::PluginRegistrarWindows *registrar_;
    // The ID of the WindowProc delegate registration.
    int window_proc_id_ = -1;

    // Called for top-level WindowProc delegation.
    std::optional<LRESULT> HandleWindowProc(
        HWND hwnd,
        UINT message,
        WPARAM wparam,
        LPARAM lparam);

  public:
    const char *AUTHORIZE_METHOD = "authorize";
    const char *AUTHORIZE_AND_EXCHANGE_CODE_METHOD = "authorizeAndExchangeCode";
    const char *TOKEN_METHOD = "token";
    const char *AUTHORIZE_ERROR_CODE = "authorize_failed";
    const char *AUTHORIZE_AND_EXCHANGE_CODE_ERROR_CODE = "authorize_and_exchange_code_failed";
    const char *DISCOVERY_ERROR_CODE = "discovery_failed";
    const char *TOKEN_ERROR_CODE = "token_failed";
    const char *DISCOVERY_ERROR_MESSAGE_FORMAT = "Error retrieving discovery document: %@";
    const char *TOKEN_ERROR_MESSAGE_FORMAT = "Failed to get token: %@";
    const char *AUTHORIZE_ERROR_MESSAGE_FORMAT = "Failed to authorize: %@";

    static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

    FlutterAppauthPlugin(flutter::PluginRegistrarWindows *registrar);

    virtual ~FlutterAppauthPlugin();

  private:
    // Called when a method is called on this plugin's channel from Dart.
    void HandleMethodCall(
        const flutter::MethodCall<flutter::EncodableValue> &method_call,
        std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

    void HandleAuthorizeMethodCall(
        const flutter::EncodableValue *args,
        bool exchangeCode);

    void HandleTokenMethodCall(
        const flutter::EncodableValue *args);

    HWND GetRootWindow(flutter::FlutterView *view)
    {
      //return view->GetNativeWindow(); //
      return GetAncestor(view->GetNativeWindow(), GA_ROOT);
    };
  };

  // static
  void FlutterAppauthPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarWindows *registrar)
  {
    const auto channel =
        std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
            registrar->messenger(), "crossingthestreams.io/flutter_appauth",
            &flutter::StandardMethodCodec::GetInstance());

    auto plugin = std::make_unique<FlutterAppauthPlugin>(registrar);

    channel->SetMethodCallHandler(
        [plugin_pointer = plugin.get()](const auto &call, auto result) {
          plugin_pointer->HandleMethodCall(call, std::move(result));
        });

    registrar->AddPlugin(std::move(plugin));
  }

  FlutterAppauthPlugin::FlutterAppauthPlugin(flutter::PluginRegistrarWindows *registrar)
      : registrar_(registrar)
  {
    window_proc_id_ = registrar_->RegisterTopLevelWindowProcDelegate(
        [this](HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
          return HandleWindowProc(hwnd, message, wparam, lparam);
        });
  }

  FlutterAppauthPlugin::~FlutterAppauthPlugin()
  {
      registrar_->UnregisterTopLevelWindowProcDelegate(window_proc_id_);
  }

  void FlutterAppauthPlugin::HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result)
  {
    if (method_call.method_name().compare(AUTHORIZE_AND_EXCHANGE_CODE_METHOD) == 0)
    {
      HandleAuthorizeMethodCall(method_call.arguments(), true);
      result->Success();
    }
    else if (method_call.method_name().compare(AUTHORIZE_METHOD) == 0)
    {
      HandleAuthorizeMethodCall(method_call.arguments(), false);
    }
    else if (method_call.method_name().compare(TOKEN_METHOD) == 0)
    {
      HandleTokenMethodCall(method_call.arguments());
    }
    else
    {
      result->NotImplemented();
    }
  }

  std::optional<LRESULT> FlutterAppauthPlugin::HandleWindowProc(
      HWND hwnd,
      UINT message,
      WPARAM wparam,
      LPARAM lparam)
  {
    return DefWindowProc(hwnd, message, wparam, lparam);
  }

  void FlutterAppauthPlugin::HandleAuthorizeMethodCall(
      const flutter::EncodableValue *args,
      bool exchangeCode)
  {
    AuthorizationTokenRequestParameters requestParameters;
    requestParameters.parse(args);

    // Create a 800 x 600 webview that shows Google
    wv::WebView w{ 800, 600, true, true, Str("Hello world2!"), Str("http://google.com") };

    if (w.init() == -1) {
        
    }

    while (w.run() == 0);

  };
  void FlutterAppauthPlugin::HandleTokenMethodCall(
      const flutter::EncodableValue *args)
  {
    TokenRequestParameters requestParameters;
    requestParameters.parse(args);
  }

} // namespace

void FlutterAppauthPluginRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar)
{
  FlutterAppauthPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
