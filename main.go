package main

import (
	"fmt"
	"net/http"

	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Data struct {
	Content string `json:content`
}

func Authorize(obj string, act string, enforcer *casbin.Enforcer, sub string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get current user/subject
		// context sub

		// Load policy from Database
		err := enforcer.LoadPolicy()
		if err != nil {
			c.AbortWithStatusJSON(500, gin.H{"msg": "Failed to load policy from DB"})
			return
		}

		// Casbin enforces policy
		ok, err := enforcer.Enforce(fmt.Sprint(sub), obj, act)

		if err != nil {
			c.AbortWithStatusJSON(500, gin.H{"msg": "Error occurred when authorizing user"})
			return
		}

		if !ok {
			c.AbortWithStatusJSON(403, gin.H{"msg": "You are not authorized"})
			return
		}
		c.Next()
	}
}

func main() {
	const (
		host     = "localhost"
		port     = 5432
		user     = "postgres"
		password = "deepak"
		dbname   = "postgres"
	)
	url := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	db, err := gorm.Open(postgres.Open(url), &gorm.Config{})

	if err != nil {
		fmt.Print(err)
	}

	fmt.Println("Connected!")

	// Initialize  casbin adapter

	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize casbin adapter: %v", err))
	}

	Router := gin.Default()
	// Load model configuration file and policy store adapter

	enforcer, err := casbin.NewEnforcer("/home/deepak/Desktop/go/test/config /rbac_model.conf", adapter)
	if err != nil {
		panic(fmt.Sprintf("failed to create casbin enforcer: %v", err))
	}

	//add policy
	if hasPolicy := enforcer.HasPolicy("Admin", "module", "edit"); !hasPolicy {
		enforcer.AddPolicy("Admin", "module", "edit")
	}
	if hasPolicy := enforcer.HasPolicy("Admin", "module", "read"); !hasPolicy {
		enforcer.AddPolicy("Admin", "module", "read")
	}
	if hasPolicy := enforcer.HasPolicy("hr", "module", "read"); !hasPolicy {
		enforcer.AddPolicy("hr", "module", "read")
	}
	if hasPolicy := enforcer.HasPolicy("hr", "module", "add"); !hasPolicy {
		enforcer.AddPolicy("hr", "module", "add")
	}
	Router.GET("/hr", Authorize("module", "read", enforcer, "hr"), ReadData) // Make request 01 takes from context
	Router.POST("/hr", Authorize("module", "edit", enforcer, "hr"), AddData)
	
	
	// 2nd 
	Router.GET("/admin", Authorize("module", "read", enforcer, "Admin"), ReadData) // Make request 01 takes from context
	Router.POST("/admin ", Authorize("module", "edit", enforcer, "Admin"), AddData)
	Router.Run("localhost:8080")
}

var content = []Data{
	{Content: "1"},
	{Content: "2"},
	{Content: "3"},
}

func ReadData(c *gin.Context) {

	c.IndentedJSON(http.StatusAccepted, content)
}
func AddData(c *gin.Context) {
	var data Data
	if err := c.BindJSON(&data); err != nil {
		c.JSON(http.StatusBadGateway, err)
		return
	}
content=append(content, data)
c.JSON(http.StatusAccepted, gin.H{"msg" : "accepted"})

}
