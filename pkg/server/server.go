package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"regexp"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"

	"gopkg.in/yaml.v3"

	"github.com/gorilla/mux"
	"github.com/itechart-tournaments/corporate-tournament-service/pkg/cts"
	uuid "github.com/satori/go.uuid"
)

type config struct {
	DBConnPort           int64  `yaml:"db_conn_port"`
	DBUser               string `yaml:"db_user"`
	DBPasswd             string `yaml:"db_pass"`
	DBName               string `yaml:"db_name"`
	SenderEmail          string `yaml:"sender_email"`
	SenderEmailPasswd    string `yaml:"sender_email_passwd"`
	SMTPHost             string `yaml:"smtp_host"`
	SMTPPort             int64  `yaml:"smtp_port"`
	PrivateKey           string `yaml:"private_key"`
	RegTokenLifeTime     int64  `yaml:"reg_token_life_time"`
	AccessTokenLifeTime  int64  `yaml:"access_token_life_time"`
	RefreshTokenLifeTime int64  `yaml:"refresh_token_life_time"`
	APIURL               string `yaml:"api_url"`
}

// Server represents а server in corporate tournament service.
type Server struct {
	http.Handler
	service cts.Service
}

var conf config

// NewServer constructs a Server, decodes yaml configuration file
// and assigns decoded values to config struct.
func NewServer(db cts.Service) *Server {

	// TODO: make path of config.yaml more concrete
	yamlConfigFile, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		log.Printf("error opening cofiguration yaml file: %s", err.Error())
		return nil
	}

	err = yaml.Unmarshal(yamlConfigFile, &conf)
	if err != nil {
		log.Printf("error unmarshaling yaml configuration file: %s", err.Error())
		return nil
	}

	router := mux.NewRouter()

	secureRouter := router.PathPrefix("/api").Subrouter()
	secureRouter.Use(jwtAuthentication)

	s := Server{
		service: db,
		Handler: router,
	}
	router.HandleFunc("/signin", s.signIn).Methods("POST")
	router.HandleFunc("/login", s.login).Methods("POST")
	router.HandleFunc("/refresh", s.refresh).Methods("GET")
	secureRouter.HandleFunc("/welcome", s.welcome).Methods("GET")
	return &s
}

func (s *Server) signIn(w http.ResponseWriter, req *http.Request) {
	user := struct {
		Email string `json:"email"`
	}{}

	err := json.NewDecoder(req.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "couldn't decode json: %s", err)
		return
	}

	token, err := uuid.NewV4()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("error creating uuid: %s", err.Error())
		return
	}

	err = sendTokenToEmail(user.Email, token.String())
	if err != nil {
		log.Printf("error sending email: %s", err.Error())
		return
	}

	expTime := time.Now().UTC().Add(time.Minute * time.Duration(conf.RegTokenLifeTime))

	err = s.service.AddToken(token.String(), user.Email, expTime)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "couldn't add token %s", err)
		return
	}
}

func (s *Server) login(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	token, ok := vars["token"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "token is not provided")
		return
	}

	err := s.service.Transactional(req.Context(), verifyToken(token))

	if err == cts.ErrNotFound {
		w.WriteHeader(http.StatusNotFound)
		log.Print(err.Error())
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// TODO: create jwt access token and refresh token and send them both
}

// Welcome
func (s *Server) welcome(w http.ResponseWriter, r *http.Request) {

}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {

}

func createJWTAccessToken(email string) (string, error) {
	expTime := time.Now().UTC().Add(time.Minute * time.Duration(conf.AccessTokenLifeTime)).Unix()
	tk := &Token{
		Email: email,
		jwt.StandardClaims{
			ExpiresAt: expTime,
		},
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)
	tokenString, err := token.SignedString([]byte(conf.privateKey))
	if err != nil {
		return "", fmt.Errorf("error create JWT access token: %s", err.Error())
	}
	return tokenString, nil
}

// sendTokenToEmail function validates given email using regExp,
// parses template file and writes result body structure to email body.
// Finally sendTokenToEmail function sends letter using smtp to address provided
// by emailTo variable. If smth goes wrong corresponding error will be returned.
func sendTokenToEmail(emailTo, token string) error {

	var validEmail = regexp.MustCompile(`[^@]+@[^@]+\.[^@]+`)
	if !validEmail.MatchString(emailTo) {
		return errors.New("email is not valid")
	}

	emailTemplate, err := template.ParseFiles("email-template.html")

	if err != nil {
		return fmt.Errorf("error parsing html template file: %s", err.Error())
	}

	headers := "MIME-version: 1.0;\nContent-Type: text/html;"
	var emailBody bytes.Buffer
	emailBody.Write([]byte(fmt.Sprintf("Subject: registration\n%s\n\n", headers)))

	err = emailTemplate.Execute(&emailBody, struct {
		RegURL          string
		Token           string
		RegTokenExpTime string
	}{
		RegURL:          conf.apiURL,
		Token:           token,
		RegTokenExpTime: conf.regTokenExpTime,
	})

	if err != nil {
		return fmt.Errorf("error applying parsed template to the specified data object: %s", err.Error())
	}

	auth := smtp.PlainAuth("", conf.SenderEmail, conf.SenderEmailPasswd, conf.smtpHost)

	err = smtp.SendMail(fmt.Sprintf("%s:%s", conf.smtpHost, conf.smtpPort), auth, conf.SenderEmail, []string{emailTo}, emailBody.Bytes())
	if err != nil {
		return fmt.Errorf("error sending email: %s", err.Error())
	}

	return nil
}

func verifyToken(token string) func(s cts.Service) error {

	return func(s cts.Service) error {

		email, err := s.GetEmail(token)

		if err != nil {
			log.Printf("error verifying token: %s", err.Error())
			return fmt.Errorf("error verifying token: %s", err.Error())
		}

		// TODO: delete token from db

		// Do we need to do smth with account id?
		_, err = s.AddAccount(email)

		if err != nil {
			log.Printf("error adding account: %s", err.Error())
			return fmt.Errorf("error adding account: %s", err.Error())
		}

		return nil
	}
}

// Token is JWT claims struct
type Token struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

func jwtAuthentication(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		tokenHeader := req.Header.Get("Authorization")

		if tokenHeader == "" {
			w.WriteHeader(http.StatusUnauthorized)
			log.Print("Missing auth token")
			return
		}

		// The token normally comes in format `Bearer {token-body}`,
		// we check if the retrieved token matched this requirement
		splitted := strings.Split(tokenHeader, " ")
		if len(splitted) != 2 {
			w.WriteHeader(http.StatusForbidden)
			log.Print("Invalid/Malformed auth token")
			return
		}

		// Grab the token part, what we are truly interested in
		tokenPart := splitted[1]
		tk := &Token{}

		token, err := jwt.ParseWithClaims(tokenPart, tk, func(token *jwt.Token) (interface{}, error) {
			return []byte(conf.privateKey), nil
		})

		// Malformed token, returns with http code 403 as usual
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			log.Print("Invalid/Malformed auth token")
			return
		}

		// Token is invalid, maybe not signed on this server
		if !token.Valid {
			w.WriteHeader(http.StatusForbidden)
			log.Print("Token is not valid")
			return
		}

		// TODO: Add ExpAt time validation here

		// Proceed in the middleware chain
		next.ServeHTTP(w, req)
	})
}
