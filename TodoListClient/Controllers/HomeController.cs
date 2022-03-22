using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Web;
using System.Diagnostics;
using System.Threading.Tasks;
using TodoListClient.Models;

namespace TodoListClient.Controllers
{
    [Authorize]
    public class HomeController : ControllerBase
    {
        public HomeController(ITokenAcquisition tokenAcquisition, ILoggerFactory loggerFactory) : base(tokenAcquisition)
        {
            _logger = loggerFactory.CreateLogger<HomeController>();
        }

        public async Task<IActionResult> Index()
        {
            await PrintAuthenticaltionDetails($"{typeof(HomeController).Name}.Index");

            return View();
        }

        [AllowAnonymous]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}