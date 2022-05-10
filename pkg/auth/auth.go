package auth
type IAuth interface {
	Init(projectId, key string)
	SignUp(username, phone, email string)
	SignIn(identifier string)
	VerifyCode(identifier, verificationCode string)
}

type Auth struct {
 	// client
	projectId string
	publicKey string
}


func (a *Auth) Init(projectId, key string) {
}

func (a *Auth) SignUp(username, phone, email string) {
}

func (a *Auth) SignIn(identifier string) {
}

func (a *Auth) VerifyCode(identifier, verificationCode string) {
}