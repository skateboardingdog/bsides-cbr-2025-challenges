package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	_ "github.com/lib/pq"
)

var db *sql.DB

type Item struct {
	Name   string `json:"name"`
	SKU    string `json:"sku"`
	Price  int    `json:"price"`
	Rating int    `json:"rating"`
	Rank   int    `json:"rank"`
}

func initDatabase() {
	var err error

	db, err = sql.Open("postgres", "host=localhost port=5432 user=shop password=shop dbname=shopdb sslmode=disable")
	if err != nil {
		log.Fatal("Failed to open database connection!")
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "/app/index.html")
}

func populateHandler(w http.ResponseWriter, r *http.Request) {
	query := strings.ReplaceAll(`
		WITH ranked_{TYPE} AS (
			SELECT 
				{TYPE}_name AS name,
				{TYPE}_sku AS sku,
				{TYPE}_price AS price,
				{TYPE}_user_rating AS rating,
				RANK() OVER (ORDER BY {TYPE}_user_rating DESC) as rank
			FROM {TYPE}
		)
		SELECT * FROM ranked_{TYPE}
		ORDER BY rank, name
		LIMIT 20
	`, "{TYPE}", r.URL.Query().Get("item"))

	rows, err := db.Query(query)
	if err != nil {
		log.Printf("Query error: %v", err)
		http.Error(w, "500", http.StatusServiceUnavailable)
		return
	}
	defer rows.Close()

	var items []Item
	for rows.Next() {
		var item Item
		err := rows.Scan(&item.Name, &item.SKU, &item.Price, &item.Rating, &item.Rank)
		if err != nil {
			log.Printf("Scan error: %v", err)
			http.Error(w, "500", http.StatusServiceUnavailable)
			return
		}
		items = append(items, item)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

func main() {
	initDatabase()
	defer db.Close()

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/populate", populateHandler)

	port := ":1337"
	log.Printf("Server starting on http://localhost%s\n", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}
