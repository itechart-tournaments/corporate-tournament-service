package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/corporate-tournament-service/pkg/cts"
	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"
)

type config struct {
	DBConnPort        string `yaml:"db_conn_port"`
	DBUser            string `yaml:"db_user"`
	DBPasswd          string `yaml:"db_pass"`
	DBName            string `yaml:"db_name"`
	SenderEmail       string `yaml:"sender_email"`
	SenderEmailPasswd string `yaml:"sender_email_passwd"`
	smtpHost          string `yaml:"smtp_host"`
	smtpPort          string `yaml:"smtp_port"`
	privateKey        string `yaml:"private_key"`
	regTokenExpTime   string `yaml:"private_key"`
	apiURL            string `yaml:"api_url"`
}

// Server represents а server in corporate tournament service.
type Server struct {
	http.Handler
	service cts.Service
}

var conf config

// NewServer constructs a Server and inits variables from config.
func NewServer(db cts.Service) *Server {

	yamlConfigFile, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		log.Printf("error opening cofiguration yaml file: %s", err.Error())
	}

	err = yaml.Unmarshal(yamlConfigFile, &conf)
	if err != nil {
		log.Printf("error unmarshal yaml configuration file: %s", err.Error())
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

	regTokenExpTime, err := strconv.ParseInt(conf.regTokenExpTime, 10, 64)
	if err != nil {
		log.Printf("wrong token expiration time provided: %s", err.Error())
		return
	}

	token, err := uuid.NewV4()

	if err != nil {
		log.Printf("error creating uuid: %s", err.Error())
		return
	}

	err = sendTokenToEmail(user.Email, token.String())

	if err != nil {
		log.Printf("error sending email: %s", err.Error())
		return
	}

	expTime := time.Now().UTC().Add(time.Minute * time.Duration(regTokenExpTime))

	err = s.service.AddToken(req.Context(), token.String(), user.Email, expTime)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "couldn't add token %s", err)
		return
	}

	// TODO: create jwt access token and refresh token and send them
}

func (s *Server) login(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	token, ok := vars["token"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "token is not provided")
		return
	}

	// Do i need to pass here w and req?
	err := s.service.Transactional(verifyToken(s.service, token))
}

// Welcome is function that checks if access token is written inside users cookie
// and if it's valid
func (s *Server) welcome(w http.ResponseWriter, r *http.Request) {

}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {

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

func verifyToken(s cts.Service, token string) func(s cts.Service) error {

	return func(s cts.Service) error {
		// TODO: get email here

		if err == cts.ErrNotFound {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("error verifying token: %s", err.Error())
			return
		}

		accountID, err := s.AddAccount(req.Context(), email)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("error adding account: %s", err.Error())
			return
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

		// Proceed in the middleware chain
		next.ServeHTTP(w, req)
	})
}
