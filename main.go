package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/rasmussecher/Chirpy/internal/auth"
	"github.com/rasmussecher/Chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	secret         string
	polkaKey       string
}

type User struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserId    uuid.UUID `json:"user_id"`
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Println("Failed to connect to database: %w", err)
		return
	}
	fmt.Println("Successfully connected to database 💾")

	apiCfg := apiConfig{
		fileserverHits: atomic.Int32{},
		db:             database.New(db),
		platform:       os.Getenv("PLATFORM"),
		secret:         os.Getenv("SECRET"),
		polkaKey:       os.Getenv("POLKA_KEY"),
	}
	mux := http.NewServeMux()

	// Routes
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /admin/metrics", apiCfg.fileserverHitsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.fileserverResetHandler)
	mux.HandleFunc("GET /api/healthz", healthCheckHandler)
	mux.HandleFunc("POST /api/users", apiCfg.usersHandler)
	mux.HandleFunc("PUT /api/users", apiCfg.updateUsersHandler)
	mux.HandleFunc("POST /api/login", apiCfg.usersLoginHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshTokenHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.refreshTokenRevokeHandler)
	mux.HandleFunc("POST /api/chirps", apiCfg.postChirpsHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.getAllChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpByIDHandler)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.polkaWebhookHandler)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirpByIDHandler)

	// Server
	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}
	fmt.Printf("Listening on localhost%s 🚀\n", server.Addr)
	server.ListenAndServe()
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("increment")
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) polkaWebhookHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			UserID uuid.UUID `json:"user_id"`
		} `json:"data"`
	}

	apiKey, err := auth.GetApiKey(r.Header)
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 401, "Missing or invalid auth token")
		return
	}

	if apiKey != cfg.polkaKey {
		w.WriteHeader(401)
		return
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 400, "Invalid JSON body")
		return
	}

	if params.Event != "user.upgraded" {
		w.WriteHeader(204)
		return
	}

	_, err = cfg.db.UpdateUserChirpyRed(r.Context(), database.UpdateUserChirpyRedParams{
		ID:          params.Data.UserID,
		IsChirpyRed: true,
	})
	if err != nil {
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(204)
}

func (cfg *apiConfig) getChirpByIDHandler(w http.ResponseWriter, r *http.Request) {
	val, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 500, err.Error())
		return
	}
	chirp, err := cfg.db.GetChirpById(r.Context(), val)
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 404, err.Error())
		return
	}
	respondWithJson(w, 200, Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserId:    chirp.UserID,
	})
}

func (cfg *apiConfig) deleteChirpByIDHandler(w http.ResponseWriter, r *http.Request) {
	val, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 500, err.Error())
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 401, "Missing or invalid auth token")
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 401, "Failed to validate JWT")
		return
	}

	chirp, err := cfg.db.GetChirpById(r.Context(), val)
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 404, "Chirp not found")
		return
	}

	if chirp.UserID != userID {
		fmt.Println("User does not have the auth to delete this Chirp:", chirp)
		w.WriteHeader(403)
		return
	}

	err = cfg.db.DeleteChirpById(r.Context(), chirp.ID)
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 404, "Chirp not found")
		return
	}

	w.WriteHeader(204)
}

func (cfg *apiConfig) getAllChirpsHandler(w http.ResponseWriter, r *http.Request) {
	chirps, err := cfg.db.GetAllChirps(r.Context())
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 404, err.Error())
		return
	}
	var jsonChirps []Chirp
	for i := range chirps {
		jsonChirps = append(jsonChirps, Chirp{
			ID:        chirps[i].ID,
			CreatedAt: chirps[i].CreatedAt,
			UpdatedAt: chirps[i].UpdatedAt,
			Body:      chirps[i].Body,
			UserId:    chirps[i].UserID,
		})
	}
	respondWithJson(w, 200, jsonChirps)
}

func (cfg *apiConfig) postChirpsHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 400, "Invalid JSON body")
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 401, "Missing or invalid auth token")
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 401, "Failed to validate JWT")
		return
	}

	if len(strings.TrimSpace(params.Body)) == 0 {
		respondWithError(w, 400, "Chirp body cannot be empty")
		return
	}
	if len(params.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long")
		return
	}

	chirp, err := cfg.db.CreateChirp(r.Context(), database.CreateChirpParams{Body: replaceProfanity(params.Body), UserID: userID})
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 500, err.Error())
		return
	}

	respondWithJson(w, 201, Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserId:    userID,
	})
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) fileserverHitsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	htmlTemplate := fmt.Sprintf(`<!DOCTYPE html>
<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())
	w.Write([]byte(htmlTemplate))
}

func (cfg *apiConfig) fileserverResetHandler(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		w.WriteHeader(403)
		return
	}
	cfg.fileserverHits.Store(0)
	cfg.db.DeleteAllUsers(r.Context())
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Deleted all hits and users")))
}

func (cfg *apiConfig) refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		RefreshToken string `json:"token"`
	}
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 401, "Missing or invalid auth token")
		return
	}
	refreshToken, err := cfg.db.GetRefreshTokenByToken(r.Context(), token)
	if err != nil || refreshToken.ExpiresAt.Before(time.Now().UTC()) || refreshToken.RevokedAt.Valid {
		fmt.Println(err)
		respondWithError(w, 401, "Error occured getting refresh token")
		return
	}
	user, err := cfg.db.GetUserFromRefreshToken(r.Context(), token)
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 401, "User not found")
		return
	}

	jwt, err := auth.MakeJWT(user.ID, cfg.secret, time.Duration(1)*time.Hour)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
		return
	}

	respondWithJson(w, 200, parameters{
		RefreshToken: jwt,
	})
}

func (cfg *apiConfig) refreshTokenRevokeHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 401, "Missing or invalid auth token")
		return
	}
	_, err = cfg.db.UpdateRefreshToken(r.Context(), database.UpdateRefreshTokenParams{
		Token:     token,
		RevokedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	})
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 500, "Server error")
		return
	}
	w.WriteHeader(204)
}

func (cfg *apiConfig) updateUsersHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	type returnUser struct {
		ID          uuid.UUID `json:"id"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 401, "Missing or invalid auth token")
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 401, "Failed to validate JWT")
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	}

	user, err := cfg.db.UpdateUser(r.Context(), database.UpdateUserParams{
		ID:             userID,
		Email:          params.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	}

	respondWithJson(w, 200, returnUser{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	})

}

func (cfg *apiConfig) usersLoginHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	}

	user, err := cfg.db.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	err = auth.CheckPasswordHash(user.HashedPassword, params.Password)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(401)
		return
	}

	token, err := auth.MakeJWT(user.ID, cfg.secret, time.Duration(1)*time.Hour)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
		return
	}

	tok, _ := auth.MakeRefreshToken()
	refreshToken, err := cfg.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     tok,
		UserID:    user.ID,
		ExpiresAt: time.Now().UTC().Add(time.Duration(1) * time.Hour),
	})
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
		return
	}

	fmt.Println("Refresh token:", refreshToken.Token)

	respondWithJson(w, 200, User{
		ID:           user.ID,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		Token:        token,
		RefreshToken: refreshToken.Token,
		IsChirpyRed:  user.IsChirpyRed,
	})

}

func (cfg *apiConfig) usersHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	}

	user, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 500, "Something went wrong")
		return
	}

	respondWithJson(w, 201, User{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	})
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type returnError struct {
		Msg string `json:"error"`
	}
	returnValue := returnError{
		Msg: msg,
	}
	dat, err := json.Marshal(returnValue)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func respondWithJson(w http.ResponseWriter, code int, payload interface{}) {
	dat, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func replaceProfanity(str string) string {
	badWords := [3]string{"kerfuffle", "sharbert", "fornax"}
	strSplit := strings.Split(str, " ")

	for i := range strSplit {
		for j := range badWords {
			if strings.ToLower(strSplit[i]) == badWords[j] {
				strSplit[i] = "****"
			}
		}
	}

	return strings.Join(strSplit, " ")
}
