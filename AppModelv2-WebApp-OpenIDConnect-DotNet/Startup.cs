using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using System.Linq;
using Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.Notifications;
using System.Web;
using System.Configuration;
using Microsoft.Identity.Client;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity;
using System.IdentityModel;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.IdentityModel.Tokens;

[assembly: OwinStartup(typeof(AppModelv2_WebApp_OpenIDConnect_DotNet.Startup))]

namespace AppModelv2_WebApp_OpenIDConnect_DotNet
{
    public class Startup
    {
        // The Client ID is used by the application to uniquely identify itself to Azure AD.
        string clientId = System.Configuration.ConfigurationManager.AppSettings["ClientId"];

        // RedirectUri is the URL where the user will be redirected to after they sign in.
        string redirectUri = System.Configuration.ConfigurationManager.AppSettings["RedirectUri"];

        // Tenant is the tenant ID (e.g. contoso.onmicrosoft.com, or 'common' for multi-tenant)
        static string tenant = System.Configuration.ConfigurationManager.AppSettings["Azure:Tenant"];

        // Authority is the URL for authority, composed by Microsoft identity platform endpoint and the tenant name (e.g. https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0)
        string authority = String.Format(System.Globalization.CultureInfo.InvariantCulture, System.Configuration.ConfigurationManager.AppSettings["Azure:Authority"], tenant);


        /// <summary>
        /// Configure OWIN to use OpenIdConnect 
        /// </summary>
        /// <param name="app"></param>
        public void Configuration(IAppBuilder app)
        {
          
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions()
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                ExpireTimeSpan = TimeSpan.FromHours(8),
            });
            //app.usecookieauthentication(new cookieauthenticationoptions
            //{
            //    // set the authentication type and cookie name.
            //    authenticationtype = defaultauthenticationtypes.applicationcookie,
            //    cookiename = "yourcookiename",

            //    // set the expiration time of the cookie.
            //    expiretimespan = timespan.fromdays(30),

            //    // set the login path.
            //    loginpath = new pathstring("/account/login"),

            //    // set the provider for validating the security stamp.
            //    provider = new cookieauthenticationprovider
            //    {
            //        onvalidateidentity = securitystampvalidator.onvalidateidentity<applicationusermanager, applicationuser>(
            //validateinterval: timespan.fromminutes(30),
            //regenerateidentity: (manager, user) => user.generateuseridentityasync(manager))
            //    }
            //});


            app.UseOpenIdConnectAuthentication(
                    new OpenIdConnectAuthenticationOptions
                    {
                        ClientId = ConfigurationManager.AppSettings["Azure:ClientId"],
                        Authority = authority,
                        RedirectUri = ConfigurationManager.AppSettings["Azure:RedirectUri"],
                        PostLogoutRedirectUri = ConfigurationManager.AppSettings["Azure:RedirectUri"],
                        Scope = ConfigurationManager.AppSettings["Azure:WebAPITokenScope"],
                        ResponseType = "code id_token",
                        TokenValidationParameters = new TokenValidationParameters
                        {
                            ValidateIssuer = true,
                            ValidIssuer = authority,
                            ValidateAudience = true,
                            ValidAudience = ConfigurationManager.AppSettings["Azure:ClientId"],
                            ValidateLifetime = true
                        },
                        Notifications = new OpenIdConnectAuthenticationNotifications
                        {
                            AuthenticationFailed = OnAuthenticationFailed,
                            AuthorizationCodeReceived = OnAuthorizationCodeReceived,
                            SecurityTokenValidated = OnSecurityTokenValidated,
                        }
                    });
        }

        [Obsolete]
        private async Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();
            notification.Response.Redirect("/Error?message=" + notification.Exception.Message);

            // Try to refresh the access token using the refresh token stored in the cookie or session
            try
            {
                var app = ConfidentialClientApplicationBuilder.Create(clientId)
                    .WithAuthority(authority)
                    .WithRedirectUri(redirectUri)
                    .WithClientSecret(ConfigurationManager.AppSettings["Azure:ClientSecret"])
                    .Build();

                var userObjId = notification.OwinContext.Authentication.User.Claims.FirstOrDefault(c => c.Type == "http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value;
                var user = notification.OwinContext.Authentication.User.Claims.FirstOrDefault(c => c.Type == "unique_name")?.Value;

                var userAc = await app.GetAccountAsync("unique_name");
                // Try to acquire an access token for the Web API using the refresh token
                var result = await app.AcquireTokenSilent(ConfigurationManager.AppSettings["Azure:WebAPITokenScope"].Split(' '), userAc).ExecuteAsync();
                var result2 = await app.AcquireTokenSilent(ConfigurationManager.AppSettings["Azure:WebAPITokenScope"].Split(' '), user).ExecuteAsync();
                var result3 = await app.AcquireTokenSilent(ConfigurationManager.AppSettings["Azure:WebAPITokenScope"].Split(' '), userAc).ExecuteAsync();
                //var result = await app.UserTokenCache()

                // Store the new access token in the session or cookie
                HttpContext.Current.Session["AccessToken"] = result.AccessToken;
                HttpContext.Current.Session["RefreshToken"] = result.IdToken;
                HttpContext.Current.Response.Cookies.Set(new HttpCookie("AccessToken", result.AccessToken));
                HttpContext.Current.Response.Cookies.Set(new HttpCookie("RefreshToken", result.IdToken));
            }
            catch (MsalUiRequiredException)
            {
                HttpContext.Current.GetOwinContext().Authentication.Challenge(new AuthenticationProperties { RedirectUri = "/" }, OpenIdConnectAuthenticationDefaults.AuthenticationType);

                // User interaction is required to refresh the token
            }
            catch (Exception ex)
            {
                // If refreshing the access token fails, redirect the user to the login page
                HttpContext.Current.GetOwinContext().Authentication.Challenge(new AuthenticationProperties { RedirectUri = "/" }, OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }
        }

        private async Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedNotification notification)
        {
            var code = notification.Code;


            // Get the access token and refresh token using the authorization code

            var authContext = ConfidentialClientApplicationBuilder.Create(ConfigurationManager.AppSettings["Azure:ClientId"])
                           .WithAuthority(authority)
                           .WithRedirectUri(ConfigurationManager.AppSettings["Azure:RedirectUri"])
                           .WithClientSecret(ConfigurationManager.AppSettings["Azure:ClientSecret"])
                           .Build();

            var result = await authContext.AcquireTokenByAuthorizationCode(ConfigurationManager.AppSettings["Azure:WebAPITokenScope"].Split(' '), code)
                    .ExecuteAsync();
            var users = authContext.GetAccountsAsync().Result.First();
            HttpContext.Current.Session["UserLoggedIn"] = users;
            HttpContext.Current.Session["AccountHome"] = users.HomeAccountId;
            // Store the access token and refresh token in the session or cookie
            //HttpContext.Current.Session["AccessToken"] = result.AccessToken;
            //HttpContext.Current.Session["RefreshToken"] = result.IdToken;
            //HttpContext.Current.Response.Cookies.Set(new HttpCookie("AccessToken", result.AccessToken));
            //HttpContext.Current.Response.Cookies.Set(new HttpCookie("RefreshToken", result.IdToken));
        }

        private async Task OnSecurityTokenValidated(SecurityTokenValidatedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            try
            {
                var authContext = ConfidentialClientApplicationBuilder.Create(ConfigurationManager.AppSettings["Azure:ClientId"])
                          .WithAuthority(authority)
                          .WithRedirectUri(ConfigurationManager.AppSettings["Azure:RedirectUri"])
                          .WithClientSecret(ConfigurationManager.AppSettings["Azure:ClientSecret"])
                          .Build();
                var userObjId = notification.AuthenticationTicket.Identity.Claims.FirstOrDefault(c => c.Type == "http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value;
               

                var user = authContext.GetAccountAsync(userObjId).Result;
                var users = authContext.GetAccountsAsync().Result.First();
                //HttpContext.Current.Session["UserLoggedIn"] = users;
                IAccount account = new IAccount({ HomeAccountId =});
                if(user == null) 
                {
                    var id = (AccountId)HttpContext.Current.Session["AccountHome"];
                    var result = await authContext.AcquireTokenSilent(ConfigurationManager.AppSettings["Azure:WebAPITokenScope"].Split(' '), IAccount)
                   .ExecuteAsync();
                }
            }
            catch (MsalUiRequiredException)
            {
                HttpContext.Current.GetOwinContext().Authentication.Challenge(new AuthenticationProperties { RedirectUri = "/" }, OpenIdConnectAuthenticationDefaults.AuthenticationType);

                // User interaction is required to refresh the token
            }
            catch (Exception ex)
            {
                // If refreshing the access token fails, redirect the user to the login page
                HttpContext.Current.GetOwinContext().Authentication.Challenge(new AuthenticationProperties { RedirectUri = "/" }, OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }

            // Store the access token and refresh token in the session or cookie
            //HttpContext.Current.Session["AccessToken"] = notification.ProtocolMessage.AccessToken;
            //HttpContext.Current.Session["RefreshToken"] = notification.ProtocolMessage.RefreshToken;
            //HttpContext.Current.Response.Cookies.Set(new HttpCookie("AccessToken", notification.ProtocolMessage.AccessToken));
            //HttpContext.Current.Response.Cookies.Set(new HttpCookie("RefreshToken", notification.ProtocolMessage.RefreshToken));
        }
    }
}

