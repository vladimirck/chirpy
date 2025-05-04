package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/vladimirck/chirpy/internal/auth"
	"github.com/vladimirck/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	secretKey      string
	polkaKey       string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		fmt.Println("Path /app visited")
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) getMetrics(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "text/html; charset=utf-8")
	res.WriteHeader(http.StatusOK)

	res.Write([]byte(fmt.Sprintf(`
	<html>
		<body>
			<h1>Welcome, Chirpy Admin</h1>
			<p>Chirpy has been visited %d times!</p>
		</body>
	</html>`,
		cfg.fileserverHits.Load())))
}

func (cfg *apiConfig) resetMetrics(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if cfg.platform != "dev" {
		res.WriteHeader(http.StatusForbidden)
		res.Write([]byte("Forbidden: Only the developer can access this endpoint"))
		return
	}

	res.WriteHeader(http.StatusOK)
	cfg.fileserverHits.Store(0)
	if err := cfg.db.DeleteAllUsers(req.Context()); err != nil {
		fmt.Printf("Error while deleting all users: %s", err)
		res.Write([]byte("Counter reset to zero\nInternal DB error while erasing all users"))
	}
	res.Write([]byte("Counter reset to zero\nAll user deleted from the database"))
}

func healthHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "text/plain; charset=utf-8")
	res.WriteHeader(http.StatusOK)
	res.Write([]byte("OK"))
}

func (cfg *apiConfig) createUser(res http.ResponseWriter, req *http.Request) {
	type jsonEmail struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	type jsonUser struct {
		Id          uuid.UUID `json:"id"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}

	decoder := json.NewDecoder(req.Body)
	jsonEmailParam := jsonEmail{}

	if err := decoder.Decode(&jsonEmailParam); err != nil {
		fmt.Printf("Error decoding the POST request parameters: %s", err)
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte("Error"))
		return
	}

	hashPasswd, err := auth.HashPassword(jsonEmailParam.Password)
	if err != nil {
		fmt.Printf("Error in hashing the password: %s", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte(fmt.Sprintf("%s", err)))
		return
	}

	user, err := cfg.db.CreateUser(
		req.Context(),
		database.CreateUserParams{
			Email:          jsonEmailParam.Email,
			HashedPassword: hashPasswd,
		})

	if err != nil {
		fmt.Printf("The user could not becreated: %s", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte(fmt.Sprintf("%s", err)))
		return
	}

	jsonUserParam := jsonUser{
		Id:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.CreatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}

	response, err := json.Marshal(jsonUserParam)
	if err != nil {
		fmt.Printf("The user could not be created: %s", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "text/json; charset=utf-8")
	res.WriteHeader(http.StatusCreated)
	res.Write(response)
}

func (cfg *apiConfig) userLogin(res http.ResponseWriter, req *http.Request) {
	type jsonEmail struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	type jsonUser struct {
		Id           uuid.UUID `json:"id"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		Email        string    `json:"email"`
		IsChirpyRed  bool      `json:"is_chirpy_red"`
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
	}

	decoder := json.NewDecoder(req.Body)
	jsonEmailParam := jsonEmail{}

	if err := decoder.Decode(&jsonEmailParam); err != nil {
		fmt.Printf("Error decoding the POST request parameters: %s", err)
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte("Error"))
		return
	}

	user, err := cfg.db.GetUserByEmail(req.Context(), jsonEmailParam.Email)

	if err != nil {
		fmt.Errorf("The user could not be found!: %s", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte(fmt.Sprintf("%s", err)))
		return
	}

	if err := auth.CheckPasswordHash(user.HashedPassword, jsonEmailParam.Password); err != nil {
		fmt.Errorf("Password does no match!: %s", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte("Incorrect email or password"))
		return
	}

	jwtDuration := time.Second * 3600

	token, err := auth.MakeJWT(user.ID, cfg.secretKey, jwtDuration)
	if err != nil {
		fmt.Printf("The token could not be generated!: %s", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte("Token could not be generated!"))
		return
	}

	refreshToken, err := auth.MakeRefreshToken()

	if err != nil {
		fmt.Printf("The refresh token could not be generated!: %s", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte("Refresh token could not be generated!"))
		return
	}

	_, err = cfg.db.SaveRefreshToken(req.Context(), database.SaveRefreshTokenParams{Token: refreshToken, UserID: user.ID})

	if err != nil {
		fmt.Printf("The refresh token could not be saved!: %s", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte("The refresh token could not be saved!"))
		return
	}

	jsonUserParam := jsonUser{
		Id:           user.ID,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		IsChirpyRed:  user.IsChirpyRed,
		Token:        token,
		RefreshToken: refreshToken,
	}

	response, err := json.Marshal(jsonUserParam)
	if err != nil {
		//fmt.Errorf("The user could not be created: %s", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "text/json; charset=utf-8")
	//res.Header().Set("Authorization", "Bearer "+token)
	res.WriteHeader(http.StatusOK)
	res.Write(response)
}

func (cfg *apiConfig) userRefreshToken(res http.ResponseWriter, req *http.Request) {
	refreshToken, err := auth.GetBearerToken(req.Header)

	if err != nil {
		fmt.Printf("No refresh token in the header: %s", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte("No refresh token in the header"))
		return
	}

	refreshTokenData, err := cfg.db.GetUserFromRefreshToken(req.Context(), refreshToken)
	if err != nil {
		fmt.Printf("No refresh token fond in the database: %s", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte("No refresh token fond in the database"))
		return
	}
	now := time.Now()

	//fmt.Printf("Now: %v\n", now)
	//fmt.Printf("Revoked Time is valid?: %v\n", refreshTokenData.RevokedAt.Valid)

	if refreshTokenData.RevokedAt.Valid {
		fmt.Printf("Refresh token was revoked: %v\n", refreshTokenData.RevokedAt.Time)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte("Refresh token was revoked"))
		return
	}

	if refreshTokenData.ExpiresAt.Before(now) {
		fmt.Printf("Refresh token has expired at %v\n", refreshTokenData.ExpiresAt)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte("Refresh token has expired"))
		return
	}

	accessToken, err := auth.MakeJWT(refreshTokenData.UserID, cfg.secretKey, time.Second*3600)
	if err != nil {
		fmt.Printf("No access token could be created: %s", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte("No access token could be created"))
		return
	}

	type jsonToken struct {
		Token string `json:"token"`
	}

	response, err := json.Marshal(jsonToken{Token: accessToken})
	if err != nil {
		fmt.Printf("No access token could be created: %s", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte("No access token could be created"))
		return
	}

	res.Header().Set("Content-Type", "text/json; charset=utf-8")
	res.WriteHeader(http.StatusOK)
	res.Write(response)
}

func (cfg *apiConfig) modifyUser(res http.ResponseWriter, req *http.Request) {
	accessToken, err := auth.GetBearerToken(req.Header)

	if err != nil {
		fmt.Printf("No access token in the header: %s", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte("No refresh token in the header"))
		return
	}

	userID, err := auth.ValidateJWT(accessToken, cfg.secretKey)

	if err != nil {
		fmt.Printf("Access token not valid!: %v", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte("Access token not valid!"))
		return
	}

	type jsonEmail struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	newUserData := jsonEmail{}

	if err := json.NewDecoder(req.Body).Decode(&newUserData); err != nil {
		fmt.Printf("Could not decode the JSON data: %v", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte("Could not decode the JSON data"))
		return
	}

	hashedPasswd, err := auth.HashPassword(newUserData.Password)
	if err != nil {
		fmt.Printf("Could not hash the user password: %v", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte("Could not hash the user password"))
		return
	}

	user, err := cfg.db.UpdateUserData(
		req.Context(),
		database.UpdateUserDataParams{
			ID:             userID,
			Email:          newUserData.Email,
			HashedPassword: hashedPasswd,
		})

	if err != nil {
		fmt.Printf("The database could not be updated with the new information: %v", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte("The database could not be updated with the new information"))
		return
	}

	type jsonUser struct {
		Id          uuid.UUID `json:"id"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}

	response, err := json.Marshal(
		jsonUser{
			Id:          user.ID,
			CreatedAt:   user.CreatedAt,
			UpdatedAt:   user.UpdatedAt,
			Email:       user.Email,
			IsChirpyRed: user.IsChirpyRed,
		})

	if err != nil {
		fmt.Printf("Was not possible to encode the response data: %v", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte("Was not possible to encode the response data"))
		return
	}

	res.Header().Set("Content-Type", "text/json; charset=utf-8")
	res.WriteHeader(http.StatusOK)
	res.Write([]byte(response))

}

func (cfg *apiConfig) userRevokeToken(res http.ResponseWriter, req *http.Request) {
	refreshToken, err := auth.GetBearerToken(req.Header)

	if err != nil {
		fmt.Printf("No refresh token in the header: %s", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte("No refresh token in the header"))
		return
	}

	_, err = cfg.db.RevokeRefreshToken(req.Context(), refreshToken)

	if err != nil {
		fmt.Printf("Token could no be revoke: %s", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte("Token could no be revoke"))
		return
	}

	res.Header().Set("Content-Type", "text/json; charset=utf-8")
	res.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) createChirp(res http.ResponseWriter, req *http.Request) {
	accessToken, err := auth.GetBearerToken(req.Header)

	if err != nil {
		fmt.Printf("No access token in the header: %s", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte("No access token in the header"))
		return
	}

	userID, err := auth.ValidateJWT(accessToken, cfg.secretKey)
	if err != nil {
		fmt.Printf("No valid access token: %s", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte("No valid access token:"))
		return
	}

	type chirpRequest struct {
		Body string `json:"body"`
	}

	type jsonChirp struct {
		Id        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserId    uuid.UUID `json:"user_id"`
	}

	type jsonError struct {
		Error string `json:"error"`
	}

	decoder := json.NewDecoder(req.Body)
	chirpRequestParam := chirpRequest{}

	fmt.Printf("First decoder\n")

	if err := decoder.Decode(&chirpRequestParam); err != nil {
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.Write([]byte("Error decondificando el mensaje"))
		res.WriteHeader(http.StatusBadRequest)
		return
	}

	fmt.Printf("Testing msg length\n")
	if len(chirpRequestParam.Body) > 140 {
		jsonErrorParam := jsonError{Error: "Chirp is too long"}
		error_data, err := json.Marshal(jsonErrorParam)
		if err != nil {
			res.Header().Set("Content-Type", "text/plain; charset=utf-8")
			res.Write([]byte("Something went wrong and Chirp is too long"))
		}
		res.Header().Set("Content-Type", "text/json; charset=utf-8")
		res.WriteHeader(400)
		res.Write(error_data)
		return
	}

	chirp, err := cfg.db.CreateChirp(req.Context(), database.CreateChirpParams{Body: chirpRequestParam.Body, UserID: userID})

	if err != nil {
		fmt.Printf("The chirp could not be created: %s", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte(fmt.Sprintf("%v", err)))
		return
	}

	jsonChirpParam := jsonChirp{
		Id:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserId:    chirp.UserID,
	}

	response_data, err := json.Marshal(jsonChirpParam)
	if err != nil {
		fmt.Printf("The chirp could not be created: %s", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "text/json; charset=utf-8")
	res.WriteHeader(http.StatusCreated)
	res.Write(response_data)

}

func (cfg *apiConfig) getChirps(res http.ResponseWriter, req *http.Request) {

	fmt.Printf("Entering createChirp\n")

	type jsonChirp struct {
		Id        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserId    uuid.UUID `json:"user_id"`
	}

	chirpsList := []database.Chirp{}
	var err error

	authorID := req.URL.Query().Get("author_id")

	if authorID != "" {
		userID, err := uuid.Parse(authorID)
		if err != nil {
			fmt.Printf("Cannot parse author ID: %v\n", err)
			res.WriteHeader(http.StatusNotFound)
			return
		}
		chirpsList, err = cfg.db.GetChirpsByUserID(req.Context(), userID)
		if err != nil {
			fmt.Printf("This author does not have any chirps: %s", err)
			res.Header().Set("Content-Type", "text/plain; charset=utf-8")
			res.WriteHeader(http.StatusNotFound)
			res.Write([]byte(fmt.Sprintf("%v", err)))
			return
		}
	} else {
		chirpsList, err = cfg.db.GetChirps(req.Context())
		if err != nil {
			fmt.Errorf("The chirp could not be created: %s", err)
			res.Header().Set("Content-Type", "text/plain; charset=utf-8")
			res.WriteHeader(http.StatusInternalServerError)
			res.Write([]byte(fmt.Sprintf("%v", err)))
			return
		}
	}

	order := req.URL.Query().Get("sort")
	if order == "desc" {
		sort.Slice(chirpsList, func(i, j int) bool { return chirpsList[i].CreatedAt.After(chirpsList[j].CreatedAt) })
	} else {
		sort.Slice(chirpsList, func(i, j int) bool { return chirpsList[i].CreatedAt.Before(chirpsList[j].CreatedAt) })
	}

	jsonChirpsList := []jsonChirp{}

	for _, chirp := range chirpsList {
		jsonChirpsList = append(jsonChirpsList,
			jsonChirp{
				Id:        chirp.ID,
				CreatedAt: chirp.CreatedAt,
				UpdatedAt: chirp.UpdatedAt,
				Body:      chirp.Body,
				UserId:    chirp.UserID,
			})
	}

	response_data, err := json.Marshal(jsonChirpsList)
	if err != nil {
		fmt.Printf("The chirp could not be created: %s", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "text/json; charset=utf-8")
	res.WriteHeader(http.StatusOK)
	res.Write(response_data)

}

func (cfg *apiConfig) getChirpByID(res http.ResponseWriter, req *http.Request) {
	chirpID, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte(fmt.Sprintf("%v", err)))
		return
	}

	type jsonChirp struct {
		Id        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserId    uuid.UUID `json:"user_id"`
	}

	chirp, err := cfg.db.GetChirpByID(req.Context(), chirpID)
	if err != nil {
		fmt.Errorf("The chirp could not be created: %s\n", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusNotFound)
		res.Write([]byte(fmt.Sprintf("%v", err)))
		return
	}

	jsonChirpParam := jsonChirp{
		Id:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserId:    chirp.UserID,
	}

	response_data, err := json.Marshal(jsonChirpParam)
	if err != nil {
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte(fmt.Sprintf("%v", err)))
		return
	}

	res.Header().Set("Content-Type", "text/json; charset=utf-8")
	res.WriteHeader(http.StatusOK)
	res.Write(response_data)

}

func (cfg *apiConfig) deleteChirpByID(res http.ResponseWriter, req *http.Request) {
	accessToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		fmt.Printf("Restricted page, the user has no authorization: %s\n", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte("Restricted page, the user has no authorization"))
		return
	}

	userID, err := auth.ValidateJWT(accessToken, cfg.secretKey)
	if err != nil {
		fmt.Printf("Access token not valid: %s\n", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusForbidden)
		res.Write([]byte("Restricted page, the user has no authorization"))
		return
	}

	chirpID, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusNotFound)
		res.Write([]byte(fmt.Sprintf("%v", err)))
		return
	}

	type jsonChirp struct {
		Id        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserId    uuid.UUID `json:"user_id"`
	}

	chirp, err := cfg.db.GetChirpByID(req.Context(), chirpID)
	if err != nil {
		fmt.Printf("The chirp could not be found: %s\n", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusNotFound)
		res.Write([]byte(fmt.Sprintf("%v", err)))
		return
	}

	if userID != chirp.UserID {
		fmt.Printf("User not authorize to delete the chirp\n")
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusForbidden)
		res.Write([]byte("User not authorize to delete the chirp"))
		return
	}

	_, err = cfg.db.DeleteChirp(req.Context(), chirpID)
	fmt.Printf("Chirp deleted: userID = %v, chirp.UserID = %v\nAccess token: %v", userID, chirp.UserID, accessToken)

	if err != nil {
		fmt.Printf("The chirp could not be deleted: %s\n", err)
		res.Header().Set("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte(fmt.Sprintf("%v", err)))
		return
	}

	res.WriteHeader(http.StatusNoContent)

}

func (cfg *apiConfig) upgradeUserPlan(res http.ResponseWriter, req *http.Request) {

	apiKey, err := auth.GetAPIKey(req.Header)
	if err != nil {
		fmt.Printf("%v\n", err)
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

	if apiKey != cfg.polkaKey {
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

	type jsonData struct {
		UserID uuid.UUID `json:"user_id"`
	}

	type jsonEvent struct {
		Event string   `json:"event"`
		Data  jsonData `json:"data"`
	}

	event := jsonEvent{}

	if err := json.NewDecoder(req.Body).Decode(&event); err != nil {
		fmt.Printf("Wrong shape: %v", err)
		res.WriteHeader(http.StatusBadRequest)
		return
	}

	if event.Event != "user.upgraded" {
		res.WriteHeader(http.StatusNoContent)
		return
	}

	_, err = cfg.db.UpgradeUserPlan(req.Context(), event.Data.UserID)

	if err != nil {
		fmt.Printf("The user could no be upgraded or was not found: %v", err)
		res.WriteHeader(http.StatusNotFound)
		return
	}

	res.WriteHeader(http.StatusNoContent)
	return
}

func main() {
	const port = "9090"
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Errorf("The postgres database cannot be opened: %s", err)
		os.Exit(1)
	}
	apiCfg := apiConfig{
		db:        database.New(db),
		platform:  os.Getenv("PLATFORM"),
		secretKey: os.Getenv("CHRIPY_SECRET"),
		polkaKey:  os.Getenv("POLKA_KEY"),
	}

	fmt.Printf("dbQueries: %v\n", apiCfg.db)

	serveMux := http.NewServeMux()
	//apiCfg := apiConfig{db: database.New(db)}

	//serveMux.Handle("/app/", http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))

	serveMux.HandleFunc("GET /api/healthz", healthHandler)
	serveMux.HandleFunc("GET /admin/metrics", apiCfg.getMetrics)
	serveMux.HandleFunc("POST /admin/reset", apiCfg.resetMetrics)
	serveMux.HandleFunc("POST /api/users", apiCfg.createUser)
	serveMux.HandleFunc("POST /api/chirps", apiCfg.createChirp)
	serveMux.HandleFunc("GET /api/chirps", apiCfg.getChirps)
	serveMux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpByID)
	serveMux.HandleFunc("POST /api/login", apiCfg.userLogin)
	serveMux.HandleFunc("POST /api/refresh", apiCfg.userRefreshToken)
	serveMux.HandleFunc("POST /api/revoke", apiCfg.userRevokeToken)
	serveMux.HandleFunc("PUT /api/users", apiCfg.modifyUser)
	serveMux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirpByID)
	serveMux.HandleFunc("POST /api/polka/webhooks", apiCfg.upgradeUserPlan)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: serveMux,
	}

	server.ListenAndServe()
}
