using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.Identity.Client;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;

namespace AppModelv2_WebApp_OpenIDConnect_DotNet.Controllers
{
    public class HomeController : Controller
    {
        // GET: Home
        public ActionResult Index()
        {
            var ceva = Session["AccessToken"];
            var altvebasd = Session["RefreshToken"];
            var asfas = Session["ASP.NET_SessionId"];
            var asffasaas = Session[".AspNet.Cookies"];
            var cevasadfaf = (IAccount)Session["UserLoggedIn"];
            //Session["HomeAccountId"] = cevasadfaf.HomeAccountId;
            //if (Session["AccessToken"] != null || Session["RefreshToken"] != null)
            //{
            //    return View();
            //}
            //else
            //{
            //    return RedirectToAction("Index", "Claims");
            //}

            if (!Request.IsAuthenticated)
            {
                return View();
            }
            else
            {
                return RedirectToAction("Index", "Claims");
            }
        }
        /// <summary>
        /// Send an OpenID Connect sign-in request.
        /// Alternatively, you can just decorate the SignIn method with the [Authorize] attribute
        /// </summary>
        public void SignIn()
        {
            if (!Request.IsAuthenticated)
            {
                HttpContext.GetOwinContext().Authentication.Challenge(
                    new AuthenticationProperties { RedirectUri = "/Claims/Index" },
                    OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }
        }

        /// <summary>
        /// Send an OpenID Connect sign-out request.
        /// </summary>
        public void SignOut()
        {
            HttpContext.GetOwinContext().Authentication.SignOut(
                    OpenIdConnectAuthenticationDefaults.AuthenticationType,
                    CookieAuthenticationDefaults.AuthenticationType);
        }
    }
}