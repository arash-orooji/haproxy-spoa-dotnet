FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /source
COPY HAProxy.StreamProcessingOffload.Agent/ ./HAProxy.StreamProcessingOffload.Agent/
COPY SharePointGuard/ ./SharePointGuard/
RUN dotnet publish SharePointGuard/SharePointGuard.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/runtime:10.0
WORKDIR /app
COPY --from=build /app .
USER $APP_UID
EXPOSE 12345
ENTRYPOINT ["dotnet", "SharePointGuard.dll"]
