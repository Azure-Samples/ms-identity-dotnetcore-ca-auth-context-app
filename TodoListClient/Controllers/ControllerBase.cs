using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Web;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TodoListClient.Controllers
{
    public abstract class ControllerBase : Controller
    {
        private readonly ITokenAcquisition _tokenAcquisition;
        protected ILogger _logger;

        public ControllerBase(ITokenAcquisition tokenAcquisition)
        {
            _tokenAcquisition = tokenAcquisition;
        }

        public async Task PrintAuthenticaltionDetails(string sourceName)
        {
            var message = "\n\n {0}: Access token acquired:\n\n {1} \n\n";

            try
            {
                PrintClaims();
                _logger.LogInformation(string.Format(message, sourceName, await _tokenAcquisition.GetAccessTokenForUserAsync(new List<string>())));

            }
            catch (System.Exception)
            {
                _logger.LogError($"\n\n{sourceName}: Access Token acquisition error. Please re-Login.\n\n");
            }
        }

        private void PrintClaims()
        {
            _logger.LogInformation("\n\n");

            foreach (var claim in User?.Claims)
            {
                _logger.LogInformation($"{claim.Type.Split('/').Last()} --> {claim.Value}");
            }

            _logger.LogInformation("\n\n");
        }

    }
}
