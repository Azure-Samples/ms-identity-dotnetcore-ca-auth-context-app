using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Web;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using TodoListClient.Models;

namespace TodoListClient.Controllers
{
    public class TodoListController : Controller
    {
        private CommonDBContext _commonDBContext;

        private IConfiguration _configuration;
        private readonly MicrosoftIdentityConsentAndConditionalAccessHandler _consentHandler;

        public TodoListController(IHttpContextAccessor contextAccessor, IConfiguration configuration, CommonDBContext commonDBContext, MicrosoftIdentityConsentAndConditionalAccessHandler consentHandler)
        {
            _configuration = configuration;
            _commonDBContext = commonDBContext;
            this._consentHandler = consentHandler;
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
        public ActionResult Index()
        {
            //reset session on every entry to TODO's list
            TodoSessionState(SessionAction.Set);

            return View(_commonDBContext.Todo.Where(l => l.Owner.Equals(HttpContext.User.Identity.Name)).ToList());
        }

        // GET: TodoList/Details/5
        public ActionResult Details(int id)
        {
            return View(_commonDBContext.Todo.FirstOrDefault(t => t.Id == id));
        }

        // GET: TodoList/Create
        public ActionResult Create()
        {
            string claimsChallenge = CheckForRequiredAuthContext(Request.Method);

            if (!string.IsNullOrWhiteSpace(claimsChallenge))
            {
                _consentHandler.ChallengeUser(new string[] { "user.read" }, claimsChallenge);

                return new EmptyResult();
            }

            var todoObject = TodoSessionState(SessionAction.Get);

            if (todoObject != null && todoObject.IsInitialized())
            {
                PersistTodo(todoObject);

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
            string claimsChallenge = CheckForRequiredAuthContext(Request.Method);

            if (!string.IsNullOrWhiteSpace(claimsChallenge))
            {
                _consentHandler.ChallengeUser(new string[] { "user.read" }, claimsChallenge);

                TodoSessionState(SessionAction.Set, todo);

                return new EmptyResult();
            }

            PersistTodo(new Todo() { Owner = HttpContext.User.Identity.Name, Title = todo.Title });

            return RedirectToAction("Index");
        }

        // GET: TodoList/Edit/5
        public ActionResult Edit(int id)
        {
            return View(_commonDBContext.Todo.FirstOrDefault(t => t.Id == id));
        }

        // POST: TodoList/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int id, [Bind("Id,Title,Owner")] Todo todo)
        {
            //await _todoListService.EditAsync(todo);
            if (id != todo.Id)
            {
                return NotFound();
            }

            _commonDBContext.Todo.Update(todo);
            _commonDBContext.SaveChanges();

            return RedirectToAction("Index");
        }

        // GET: TodoList/Delete/5
        public ActionResult Delete(int id)
        {
            return View(_commonDBContext.Todo.FirstOrDefault(t => t.Id == id));
        }

        // POST: TodoList/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, [Bind("Id,Title,Owner")] Todo todo)
        {
            string claimsChallenge = CheckForRequiredAuthContext("Delete");

            if (!string.IsNullOrWhiteSpace(claimsChallenge))
            {
                _consentHandler.ChallengeUser(new string[] { "user.read" }, claimsChallenge);
                return new EmptyResult();
            }

            var todo2 = _commonDBContext.Todo.Find(id);
            if (todo2 != null)
            {
                _commonDBContext.Todo.Remove(todo2);
                _commonDBContext.SaveChanges();
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

        private void PersistTodo(Todo todo)
        {
            _commonDBContext.Todo.Add(todo);
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

        private enum SessionAction
        {
            Set,
            Get
        }
    }
}