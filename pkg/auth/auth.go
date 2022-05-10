package auth

type Auth interface {
	Init(projectId, key string)
	SignUp(username, phone, email string)
	SignIn(identifier string)
	VerifyCode(identifier, verificationCode string)
}