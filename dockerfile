    # 1. Usa a imagem do .NET SDK para compilar o projeto
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY . .

RUN ls -R

RUN dotnet publish "CommunitySafe.Api/Projects/CommunitySafe.Api/CommunitySafe.Api.csproj" -c Release -o /app/publish /p:UseAppHost=false

# 2. Usa a imagem mais leve apenas para rodar a API (Produção)
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .

# 3. O Render exige que a aplicação rode na porta 8080 ou utilize a variável PORT
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080

# 4. Comando para iniciar sua API (substitua pelo nome da sua DLL)
ENTRYPOINT ["dotnet", "CommunitySafe.Api.dll"]