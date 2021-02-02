#include "include/flutter_appauth/flutter_appauth_plugin.h"
#include "include/flutter_appauth/web_browser.h"

// This must be included before many other Windows headers.
#include <windows.h>

// For getPlatformVersion; remove unless needed for your plugin implementation.
#include <VersionHelpers.h>

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>

#include <map>
#include <memory>
#include <sstream>

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
    // @property(nonatomic, strong) NSArray *scopes;
    // @property(nonatomic, strong) NSDictionary *serviceConfigurationParameters;
    // @property(nonatomic, strong) NSDictionary *additionalParameters;
    bool preferEphemeralSession = false;

  public:
    void parse(const flutter::EncodableValue *args)
    {
      const auto *arguments = std::get_if<flutter::EncodableMap>(args);
      if (arguments)
        processArguments(arguments);
    };

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

      // _scopes = [ArgumentProcessor processArgumentValue:arguments withKey:@"scopes"];
      // _serviceConfigurationParameters = [ArgumentProcessor processArgumentValue:arguments withKey:@"serviceConfiguration"];
      // _additionalParameters = [ArgumentProcessor processArgumentValue:arguments withKey:@"additionalParameters"];
      // _preferEphemeralSession = [[ArgumentProcessor processArgumentValue:arguments withKey:@"preferEphemeralSession"] isEqual:@YES];
      // const auto pes = arguments->find(flutter::EncodableValue("preferEphemeralSession"));
      // if (pes != arguments->end() && !pes->second.IsNull())
      //   preferEphemeralSession = std::get<bool>(gt->second);
    }
  };

  struct AuthorizationTokenRequestParameters : public TokenRequestParameters
  {
    std::string loginHint;
    //@property(nonatomic, strong) NSArray *promptValues;

  protected:
    void processArguments(const flutter::EncodableMap *arguments) override
    {
      TokenRequestParameters::processArguments(arguments);

      const auto lh = arguments->find(flutter::EncodableValue("loginHint"));
      if (lh != arguments->end() && !lh->second.IsNull())
        loginHint = std::get<std::string>(lh->second);
      // _promptValues = [ArgumentProcessor processArgumentValue:arguments withKey:@"promptValues"];
    };
  };

  class FlutterAppauthPlugin : public flutter::Plugin
  {
  #define btnBack 1
  private:
    // The registrar for this plugin, for accessing the window.
    flutter::PluginRegistrarWindows *registrar_;
    // The ID of the WindowProc delegate registration.
    int window_proc_id_ = -1;
    WebBrowser *webBrowser1;

    // Called for top-level WindowProc delegation.
    std::optional<LRESULT> HandleWindowProc(HWND hwnd, UINT message,
                                            WPARAM wparam, LPARAM lparam);

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
      return view->GetNativeWindow();//
      //return GetAncestor(view->GetNativeWindow(), GA_ROOT);
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

    // if (method_call.method_name().compare("getPlatformVersion") == 0) {
    //   std::ostringstream version_stream;
    //   version_stream << "Windows ";
    //   if (IsWindows10OrGreater()) {
    //     version_stream << "10+";
    //   } else if (IsWindows8OrGreater()) {
    //     version_stream << "8";
    //   } else if (IsWindows7OrGreater()) {
    //     version_stream << "7";
    //   }
    //   result->Success(flutter::EncodableValue(version_stream.str()));
    // } else {
    //   result->NotImplemented();
    // }
  }

  std::optional<LRESULT> FlutterAppauthPlugin::HandleWindowProc(
      HWND hwnd,
      UINT message,
      WPARAM wparam,
      LPARAM lparam)
  {
    std::optional<LRESULT> result;
     switch (message)
     {
     case WM_CREATE:
     break;
		  // CreateWindowEx(0, _T("BUTTON"),
			// 		   _T("<<< Back"),
			// 		   WS_CHILD | WS_VISIBLE,
			// 		   5, 5,
			// 		   80, 30,
			// 		   hwnd, (HMENU) btnBack, registrar_->texture_registrar->, NULL);
    case WM_SIZE:
      if (webBrowser1 != 0)
      {
        RECT rcClient;
       // auto hWndMain = GetRootWindow(registrar_->GetView());
        GetClientRect(hwnd, &rcClient);

        RECT rc;
        rc.left = 0;
        rc.top = 45;
        rc.right = rcClient.right;
        rc.bottom = rcClient.bottom;
        if (webBrowser1 != 0)
        {
          webBrowser1->SetRect(rc);
          result = 0;
        }
      }
      break;
    // case WM_GETMINMAXINFO:
    //   if (webBrowser1 != 0)
    //   {
    //     RECT rcClient;
    //     auto hWndMain = GetRootWindow(registrar_->GetView());
    //     GetClientRect(hWndMain, &rcClient);

    //     RECT rc;
    //     rc.left = 0;
    //     rc.top = 45;
    //     rc.right = rcClient.right;
    //     rc.bottom = rcClient.bottom;
    //     if (webBrowser1 != 0)
    //       webBrowser1->SetRect(rc);
    //     result = 0;
    //   }
    //   break;
    }
   // result = 0;
    return result;
  }

  void FlutterAppauthPlugin::HandleAuthorizeMethodCall(
      const flutter::EncodableValue *args,
      bool exchangeCode)
  {
    AuthorizationTokenRequestParameters requestParameters;
    requestParameters.parse(args);
    auto hWndMain = GetRootWindow(registrar_->GetView());

    RECT rcClient;
    GetClientRect(hWndMain, &rcClient);

    webBrowser1 = new WebBrowser(hWndMain);
    RECT rc;
    rc.left = 0;
    rc.top = 45;
    rc.right = rcClient.right;
    rc.bottom = rcClient.bottom;
    webBrowser1->SetRect(rc);
    webBrowser1->Navigate(_T("https://www.bing.com/"));
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
