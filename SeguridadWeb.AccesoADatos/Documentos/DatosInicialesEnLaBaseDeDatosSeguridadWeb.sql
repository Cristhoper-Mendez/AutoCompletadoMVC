USE [SeguridadWebdb]
GO
INSERT INTO [dbo].[Rol]
           ([Nombre])
     VALUES
           ('ADMINISTRADOR DEL SISTEMA')
GO
-- Encriptar la contraseña Admin2021 en MD5 https://www.infranetworking.com/md5
INSERT INTO [dbo].[Usuario]
           ([IdRol]
           ,[Nombre]
           ,[Apellido]
           ,[Login]
           ,[Password]
           ,[Estatus]
           ,[FechaRegistro])
     VALUES
           ((Select Top 1 Id from Rol where Nombre='ADMINISTRADOR DEL SISTEMA'),
           'Administrador',
           'Del Sistema',
           'SysAdmin',
           '1fe57b020cf7bcd8ef4cc23354b214a9',
           1,
           SYSDATETIME())