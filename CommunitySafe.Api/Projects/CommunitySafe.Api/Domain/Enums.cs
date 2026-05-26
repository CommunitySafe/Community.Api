namespace CommunitySafe.Api.Domain;

public enum UserRole
{
    Morador = 1,
    Organizador = 2,
    Administrador = 3
}

public enum ConsentPurpose
{
    Cadastro = 1,
    Geolocalizacao = 2,
    Notificacoes = 3,
    Marketing = 4
}

public enum AuditEventType
{
    LoginSucesso = 1,
    LoginFalha = 2,
    LogoutSucesso = 3,
    DoisFAVerificadoSucesso = 4,
    DoisFAVerificadoFalha = 5,
    RefreshTokenRotacionado = 6,
    RefreshTokenReuso = 7,
    RegistroSucesso = 8,
    RegistroFalha = 9,
    RecuperacaoSenhaSolicitada = 10,
    SenhaRedefinida = 11,
    ContaBloqueada = 12,
    ConsentimentoRegistrado = 13,
    ConsentimentoRevogado = 14,
    DadosExportados = 15,
    ContaExcluida = 16,
    OtpEmailEnviado = 17,
    OtpEmailVerificado = 18,
    OtpEmailFalha = 19
}

public enum OtpPurpose
{
    TwoFactorLogin = 1,
    PasswordReset = 2
}
