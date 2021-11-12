using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

/********************************/
using SeguridadWeb.EntidadesDeNegocio;
using SeguridadWeb.LogicaDeNegocio;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;

using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;

namespace SeguridadWeb.UI.AppWebAspCore.Controllers
{
    //[Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
    public class UsuarioController : Controller
    {
        UsuarioBL usuarioBL = new UsuarioBL();
        RolBL rolBL = new RolBL();

        private readonly HttpClient _httpClient;
        public UsuarioController(HttpClient client)
        {
            _httpClient = client;
        }

        // GET: UsuarioController
        public async Task<IActionResult> Index(Usuario pUsuario = null)
        {
            if (pUsuario == null)
                pUsuario = new Usuario();
            if (pUsuario.Top_Aux == 0)
                pUsuario.Top_Aux = 10;
            else if (pUsuario.Top_Aux == -1)
                pUsuario.Top_Aux = 0;

            var roles = new List<Rol>();
            var usuarios = new List<Usuario>();

            var resUsuario = await _httpClient.PostAsJsonAsync("Usuario/Buscar", pUsuario);
            var resRol = await _httpClient.GetAsync("Rol");

            if (resUsuario.IsSuccessStatusCode && resRol.IsSuccessStatusCode)
            {
                var bodyRol = await resRol.Content.ReadAsStringAsync();
                roles = JsonSerializer.Deserialize<List<Rol>>(bodyRol,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                var bodyUsuario = await resUsuario.Content.ReadAsStringAsync();
                usuarios = JsonSerializer.Deserialize<List<Usuario>>(bodyUsuario,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }



            ViewBag.Top = pUsuario.Top_Aux;
            ViewBag.Roles = roles;
            return View(usuarios);
        }

        // GET: UsuarioController/Details/5
        public async Task<IActionResult> Details(int id)
        {
            var usuario = new Usuario();

            var resUsuario = await _httpClient.GetAsync("Usuario/" + id);

            if (resUsuario.IsSuccessStatusCode)
            {
                var bodyUsuario = await resUsuario.Content.ReadAsStringAsync();
                usuario = JsonSerializer.Deserialize<Usuario>(bodyUsuario,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                var resRol = await _httpClient.GetAsync("Rol/" + usuario.IdRol);

                if (resRol.IsSuccessStatusCode)
                {
                    var bodyRol = await resRol.Content.ReadAsStringAsync();
                    usuario.Rol = JsonSerializer.Deserialize<Rol>(bodyRol,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                }
            }
            return View(usuario);
        }

        // GET: UsuarioController/Create
        public async Task<IActionResult> Create()
        {
            var resRol = await _httpClient.GetAsync("Rol");

            if (resRol.IsSuccessStatusCode)
            {
                var bodyRol = await resRol.Content.ReadAsStringAsync();
                ViewBag.Roles = JsonSerializer.Deserialize<List<Rol>>(bodyRol,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }
            ViewBag.Error = "";
            return View();
        }

        // POST: UsuarioController/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Usuario pUsuario)
        {
            try
            {
                var response = await _httpClient.PostAsJsonAsync("Usuario", pUsuario);

                if (response.IsSuccessStatusCode)
                {
                    return RedirectToAction(nameof(Index));
                }
                else
                {
                    ViewBag.Error = "Sucedio un error al consumir la WEP API";
                    return View(pUsuario);
                }

            }
            catch (Exception ex)
            {
                var response = await _httpClient.GetAsync("Rol");
                if (response.IsSuccessStatusCode)
                {
                    var body = await response.Content.ReadAsStringAsync();
                    ViewBag.Roles = JsonSerializer.Deserialize<List<Rol>>(body,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                }
                ViewBag.Error = ex.Message;
                return View(pUsuario);
            }
        }

        // GET: UsuarioController/Edit/5
        public async Task<IActionResult> Edit(Usuario pUsuario)
        {
            var usuario = new Usuario();
            var roles = new List<Rol>();
            var resUsuario = await _httpClient.GetAsync("Usuario/" + pUsuario.Id);
            var resRoles = await _httpClient.GetAsync("Rol");

            if (resUsuario.IsSuccessStatusCode && resRoles.IsSuccessStatusCode)
            {
                // Obtener usuario
                var bodyUsuario = await resUsuario.Content.ReadAsStringAsync();
                usuario = JsonSerializer.Deserialize<Usuario>(bodyUsuario,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                // Obtener rol de usuario
                var resRol = await _httpClient.GetAsync("Rol/" + usuario.IdRol);
                if (resRol.IsSuccessStatusCode)
                {
                    var bodyRol = await resRol.Content.ReadAsStringAsync();
                    usuario.Rol = JsonSerializer.Deserialize<Rol>(bodyRol,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                }

                // Obtener roles
                var bodyRoles = await resRoles.Content.ReadAsStringAsync();
                roles = JsonSerializer.Deserialize<List<Rol>>(bodyRoles,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }

            ViewBag.Error = "";
            ViewBag.Roles = roles;

            return View(usuario);
        }

        // POST: UsuarioController/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, Usuario pUsuario)
        {
            pUsuario.ConfirmPassword_aux = pUsuario.Password;

            try
            {
                var response = await _httpClient.PutAsJsonAsync("Usuario/" + id, pUsuario);

                if (response.IsSuccessStatusCode)
                {
                    return RedirectToAction(nameof(Index));
                }
                else
                {
                    var resRoles = await _httpClient.GetAsync("Rol");

                    if (resRoles.IsSuccessStatusCode)
                    {
                        var bodyRoles = await resRoles.Content.ReadAsStringAsync();
                        ViewBag.Roles = JsonSerializer.Deserialize<List<Rol>>(bodyRoles,
                            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    }

                    ViewBag.Error = "Ocurrio un error en la API " + response.ReasonPhrase.Trim();
                    return View(pUsuario);
                }
            }
            catch (Exception ex)
            {
                ViewBag.Error = ex.Message;
                ViewBag.Roles = await rolBL.ObtenerTodosAsync();
                return View(pUsuario);
            }
        }

        // GET: UsuarioController/Delete/5
        public async Task<IActionResult> Delete(Usuario pUsuario)
        {
            var usuario = new Usuario();
            var resUsuario = await _httpClient.GetAsync("Usuario/" + pUsuario.Id);

            if (resUsuario.IsSuccessStatusCode)
            {
                var bodyUsuario = await resUsuario.Content.ReadAsStringAsync();
                usuario = JsonSerializer.Deserialize<Usuario>(bodyUsuario,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                var resRol = await _httpClient.GetAsync("Rol/" + usuario.IdRol);
                if (resRol.IsSuccessStatusCode)
                {
                    var bodyRol = await resRol.Content.ReadAsStringAsync();
                    usuario.Rol = JsonSerializer.Deserialize<Rol>(bodyRol,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                }
            }
            ViewBag.Error = "";
            return View(usuario);
        }

        // POST: UsuarioController/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(int id, Usuario pUsuario)
        {
            try
            {
                var response = await _httpClient.DeleteAsync("Usuario/" + id);

                if (response.IsSuccessStatusCode)
                {

                    return RedirectToAction(nameof(Index));
                }
                else
                {
                    return View(pUsuario);
                }
            }
            catch (Exception ex)
            {
                ViewBag.Error = ex.Message;
                return View(pUsuario);
            }
        }
        // GET: UsuarioController/Create
        [AllowAnonymous]
        public async Task<IActionResult> Login(string ReturnUrl = null)
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            ViewBag.Url = ReturnUrl;
            ViewBag.Error = "";
            return View();
        }

        // POST: UsuarioController/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> Login(Usuario pUsuario, string pReturnUrl = null)
        {
            try
            {
                var usuario = await usuarioBL.LoginAsync(pUsuario);
                if (usuario != null && usuario.Id > 0 && pUsuario.Login == usuario.Login)
                {
                    usuario.Rol = await rolBL.ObtenerPorIdAsync(new Rol { Id = usuario.IdRol });
                    var claims = new[] { new Claim(ClaimTypes.Name, usuario.Login), new Claim(ClaimTypes.Role, usuario.Rol.Nombre) };
                    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
                }
                else
                    throw new Exception("Credenciales incorrectas");
                if (!string.IsNullOrWhiteSpace(pReturnUrl))
                    return Redirect(pReturnUrl);
                else
                    return RedirectToAction("Index", "Home");
            }
            catch (Exception ex)
            {
                ViewBag.Url = pReturnUrl;
                ViewBag.Error = ex.Message;
                return View(new Usuario { Login = pUsuario.Login });
            }
        }
        [AllowAnonymous]
        public async Task<IActionResult> CerrarSesion(string ReturnUrl = null)
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login", "Usuario");
        }
        // GET: UsuarioController/Create
        public async Task<IActionResult> CambiarPassword()
        {

            var usuarios = await usuarioBL.BuscarAsync(new Usuario { Login = User.Identity.Name, Top_Aux = 1 });
            var usuarioActual = usuarios.FirstOrDefault();
            ViewBag.Error = "";
            return View(usuarioActual);
        }

        // POST: UsuarioController/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CambiarPassword(Usuario pUsuario, string pPasswordAnt)
        {
            try
            {
                int result = await usuarioBL.CambiarPasswordAsync(pUsuario, pPasswordAnt);
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                return RedirectToAction("Login", "Usuario");
            }
            catch (Exception ex)
            {
                ViewBag.Error = ex.Message;
                var usuarios = await usuarioBL.BuscarAsync(new Usuario { Login = User.Identity.Name, Top_Aux = 1 });
                var usuarioActual = usuarios.FirstOrDefault();
                return View(usuarioActual);
            }
        }
    }
}
