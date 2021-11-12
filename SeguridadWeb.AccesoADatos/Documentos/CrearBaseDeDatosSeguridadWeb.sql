USE [master]
GO
CREATE DATABASE [SeguridadWebdb]
GO
USE [SeguridadWebdb]
GO
-- Crear la tabla de Rol
CREATE TABLE [dbo].[Rol](
  [Id] [int] PRIMARY KEY IDENTITY(1,1) NOT NULL,
  [Nombre] [varchar](30) NOT NULL
)
GO
-- Crear la tabla de Usuario
CREATE TABLE [dbo].[Usuario](
   [Id] [int] PRIMARY KEY IDENTITY(1,1) NOT NULL,
   [IdRol] [int] NOT NULL,
   [Nombre] [varchar](30) NOT NULL,
   [Apellido] [varchar](30) NOT NULL,
   [Login] [varchar](25) NOT NULL,
   [Password] [char](32) NOT NULL,
   [Estatus] [tinyint] NOT NULL,
   [FechaRegistro] [datetime] NOT NULL,
   CONSTRAINT FK1_Rol_Usuario FOREIGN KEY (IdRol) REFERENCES Rol (Id)
)