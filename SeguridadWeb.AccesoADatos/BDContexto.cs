using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
// ********************************
using Microsoft.EntityFrameworkCore;
using SeguridadWeb.EntidadesDeNegocio;

namespace SeguridadWeb.AccesoADatos
{
    public class BDContexto : DbContext
    {
        public DbSet<Rol> Rol { get; set; }
        public DbSet<Usuario> Usuario { get; set; }
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            //string conexion pc
            optionsBuilder.UseSqlServer(@"Data Source=DESKTOP-URUNQ5U\SQLEXPRESS;Initial Catalog=SeguridadWebdb;Integrated Security=True");

            //optionsBuilder.UseSqlServer(@"Data Source=LAPTOP-I2KG7UCJ\SQLEXPRESS;Initial Catalog=SeguridadWebdb;Integrated Security=True");
        }
    }
}
