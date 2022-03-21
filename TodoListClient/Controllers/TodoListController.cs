using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Web;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using TodoListClient.Models;

namespace TodoListClient.Controllers
{
    public class TodoListController : ControllerBase
    {
        private CommonDBContext _commonDBContext;

        private IConfiguration _configuration;
        private readonly MicrosoftIdentityConsentAndConditionalAccessHandler _consentHandler;

        public TodoListController(
            ITokenAcquisition tokenAcquisition, ILoggerFactory loggerFactory,
            IHttpContextAccessor contextAccessor, IConfiguration configuration,
            CommonDBContext commonDBContext, MicrosoftIdentityConsentAndConditionalAccessHandler consentHandler) : base(tokenAcquisition)
        {
            _configuration = configuration;
            _commonDBContext = commonDBContext;
            this._consentHandler = consentHandler;

            _logger = loggerFactory.CreateLogger<TodoListController>();
        }

        // GET: api/values
        [HttpGet]
        public IEnumerable<Todo> Get()
        {
            return _commonDBContext.Todo.ToList();
        }

        // GET: api/values
        [HttpGet("{id}", Name = "Get")]
        public Todo Get(int id)
        {
            return _commonDBContext.Todo.FirstOrDefault(t => t.Id == id);
        }

        // GET: TodoList
        [AuthorizeForScopes(ScopeKeySection = "TodoList:TodoListScope")]
        public async Task<ActionResult> Index()
        {
            await PrintAccessToken($"{typeof(TodoListController)}.Index");

            //reset session on every entry to TODO's list
            TodoSessionState(SessionAction.Set);

            return View(_commonDBContext.Todo.Where(l => l.AccountId.Equals(HttpContext.User.GetMsalAccountId())).ToList());
        }

        // GET: TodoList/Details/5
        public ActionResult Details(int id)
        {
            return View(_commonDBContext.Todo.FirstOrDefault(t => t.Id == id));
        }

        // GET: TodoList/Create
        public ActionResult Create()
        {
            if (ChallengeUser(Request.Method))
            {
                return RedirectToAction("Create");
            }

            //get todo from session state (if available then this means we were redirected from POST and have to save this todo)
            var todoFromSessionState = TodoSessionState(SessionAction.Get);

            if (todoFromSessionState != null && todoFromSessionState.IsInitialized)
            {
                SaveToDatabase(todoFromSessionState);

                //clean session state
                TodoSessionState(SessionAction.Set);

                return RedirectToAction("Index");
            }

            Todo todo = new Todo() { Owner = HttpContext.User.Identity.Name };

            return View(todo);
        }

        // POST: TodoList/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create([Bind("Title,Owner")] Todo todo)
        {
            //add owner accountid to new todo
            todo.AccountId = HttpContext.User.GetMsalAccountId();
            todo.Owner = HttpContext.User.Identity.Name;

            if (ChallengeUser(Request.Method))
            {
                //save in session state before redirecting to GET handler
                TodoSessionState(SessionAction.Set, todo);

                return RedirectToAction("Create");
            }

            SaveToDatabase(new Todo() { Owner = todo.Owner, Title = todo.Title, AccountId = todo.AccountId });

            return RedirectToAction("Index");
        }

        // GET: TodoList/Edit/5
        public ActionResult Edit(int id)
        {
            //get todo from session state (if available then this means we were redirected from POST and have to update this todo)
            var todoFromSessionState = TodoSessionState(SessionAction.Get);

            if (todoFromSessionState != null && todoFromSessionState.IsInitialized && todoFromSessionState.Id == id)
            {
                UpdateDatabase(todoFromSessionState);

                //clean session state
                TodoSessionState(SessionAction.Set);

                return RedirectToAction("Index");
            }
            else
            {
                return View(_commonDBContext.Todo.FirstOrDefault(t => t.Id == id));
            }
        }

        // POST: TodoList/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int id, [Bind("Id,Title,Owner")] Todo todo)
        {
            if (id != todo.Id)
            {
                return NotFound();
            }

            todo.AccountId = HttpContext.User.GetMsalAccountId();

            if (ChallengeUser(Request.Method))
            {
                //save in session state before redirecting to GET handler
                TodoSessionState(SessionAction.Set, todo);

                return RedirectToAction("Edit");
            }

            UpdateDatabase(todo);

            return RedirectToAction("Index");
        }

        // GET: TodoList/Delete/5
        public ActionResult Delete(int id)
        {
            //get todo from session state (if available then this means we were redirected from POST and have to save this todo)
            var todoFromSessionState = TodoSessionState(SessionAction.Get);

            if (todoFromSessionState != null && todoFromSessionState.Id == id)
            {
                DeleteFromDatabase(todoFromSessionState);

                //clean session state
                TodoSessionState(SessionAction.Set);

                return RedirectToAction("Index");
            }
            else
            {
                return View(_commonDBContext.Todo.FirstOrDefault(t => t.Id == id));
            }
        }

        // POST: TodoList/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, [Bind("Id,Title,Owner")] Todo todo)
        {
            if (ChallengeUser(HttpMethods.Delete))
            {
                //save in session state before redirecting to GET handler
                TodoSessionState(SessionAction.Set, new Todo { Id = id });

                return RedirectToAction("Delete");
            }

            //make sure the received todo is inside database before deleting
            var todoFromDb = _commonDBContext.Todo.Find(id);
            if (todoFromDb != null)
            {
                DeleteFromDatabase(todoFromDb);
            }

            return RedirectToAction("Index");
        }

        /// <summary>
        /// Retrieves the acrsValue from database for the request method.
        /// Checks if the access token has acrs claim with acrsValue.
        /// If does not exists then it generates a claims payload to be sent to /authorize endpoint
        /// </summary>
        /// <param name="method"></param>
        /// <returns></returns>
        public string CheckForRequiredAuthContext(string method)
        {
            string claimsChallenge = string.Empty;

            string savedAuthContextId = _commonDBContext.AuthContext.FirstOrDefault(x => x.Operation == method && x.TenantId == _configuration["AzureAD:TenantId"])?.AuthContextId;

            if (!string.IsNullOrEmpty(savedAuthContextId))
            {
                HttpContext context = this.HttpContext;

                string authenticationContextClassReferencesClaim = "acrs";

                if (context == null || context.User == null || context.User.Claims == null || !context.User.Claims.Any())
                {
                    throw new ArgumentNullException("No Usercontext is available to pick claims from");
                }

                Claim acrsClaim = context.User.FindAll(authenticationContextClassReferencesClaim).FirstOrDefault(x => x.Value == savedAuthContextId);

                if (acrsClaim?.Value != savedAuthContextId)
                {
                    claimsChallenge = "{\"id_token\":{\"acrs\":{\"essential\":true,\"value\":\"" + savedAuthContextId + "\"}}}";
                }
            }

            return claimsChallenge;
        }

        private void DeleteFromDatabase(Todo todoToRemove)
        {
            _commonDBContext.Todo.Remove(todoToRemove);
            _commonDBContext.SaveChanges();
        }

        private void SaveToDatabase(Todo todoToSave)
        {
            _commonDBContext.Todo.Add(todoToSave);
            _commonDBContext.SaveChanges();
        }

        private void UpdateDatabase(Todo todoToUpdate)
        {
            _commonDBContext.Todo.Update(todoToUpdate);
            _commonDBContext.SaveChanges();
        }

        /// <summary>
        /// Set/Get ToDo List item in session state in case of the flow redirected to GET method
        /// </summary>
        /// <param name="action">Actual action of Set or Get the session state</param>
        /// <param name="todo">Data to persist</param>
        private Todo TodoSessionState(SessionAction action, Todo todo = null)
        {
            string todoObject = "Todo";

            switch (action)
            {
                case SessionAction.Set:
                    HttpContext.Session.SetString(todoObject, todo != null ? JsonSerializer.Serialize(todo) : "");
                    break;

                case SessionAction.Get:
                    var obj = HttpContext.Session.GetString(todoObject);
                    return !string.IsNullOrEmpty(obj) ? JsonSerializer.Deserialize<Todo>(obj) : null;

                default:
                    break;
            }

            return todo;
        }

        /// <summary>
        /// Create a user challenge for the specified scope if it was requested by CAE 
        /// </summary>
        /// <param name="actionName"></param>
        /// <returns></returns>
        private bool ChallengeUser(string actionName)
        {
            string claimsChallenge = CheckForRequiredAuthContext(actionName);

            if (!string.IsNullOrWhiteSpace(claimsChallenge))
            {
                _consentHandler.ChallengeUser(new string[] { "user.read" }, claimsChallenge);

                return true;
            }

            return false;
        }

        /// <summary>
        /// Enumerator to distingush between session state actions
        /// </summary>
        private enum SessionAction
        {
            Set,
            Get
        }
    }
}