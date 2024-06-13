package authentication

import (
	"WlFrame-gin/conf"
	"WlFrame-gin/utils/global"
	"fmt"
	"github.com/casbin/casbin"
	xormadapter "github.com/casbin/xorm-adapter"
	"github.com/gin-gonic/gin"
	"log"
)

var Enforcer *casbin.Enforcer

// TODO 初始化casbin
func CasbinSetup() {
	global.DBConfig = conf.GetDatabaseConfig()

	dataSourceName := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8",
		global.DBConfig.Username,
		global.DBConfig.Password,
		global.DBConfig.Host,
		global.DBConfig.Port,
		global.DBConfig.DbName,
	)
	a := xormadapter.NewAdapter("mysql", dataSourceName, true)

	e := casbin.NewEnforcer("conf/rbac_models.conf", a)

	// 自定义匹配器，忽略请求方法的检查
	e.AddFunction("ignoreMethod", func(args ...interface{}) (interface{}, error) {
		sub, obj, _ := args[0].(string), args[1].(string), args[2].(string)
		// 忽略请求方法，只检查角色和路径
		return e.Enforce(sub, obj), nil
	})

	Enforcer = e
}

// TODO 拦截器
func Rbac() gin.HandlerFunc {
	return func(c *gin.Context) {
		var e *casbin.Enforcer
		e = Enforcer

		//从mysql中加载策略
		err := e.LoadPolicy()
		if err != nil {
			log.Println("从mysql中加载策略失败", err)
		}

		//获取请求的URI
		obj := c.Request.URL.RequestURI()
		//获取请求方法
		act := c.Request.Method
		//获取用户的角色,从db中读取
		sub := "admin"

		log.Println(obj, act, sub)

		//判断策略中是否存在
		if ok := e.Enforce(sub, obj, act); ok {
			fmt.Println("权限验证通过")
			c.Next()
		} else {
			fmt.Println("很遗憾,权限验证没有通过")
			c.Abort()
		}
	}
}
