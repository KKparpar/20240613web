package router

import (
	"WlFrame-gin/app/medical/server"
	"WlFrame-gin/utils/authentication"

	"github.com/gin-gonic/gin"
)

func MedicalRouter(e *gin.Engine) {
	system := e.Group("/api/v1/medical", authentication.Rbac())
	//结果
	{
		system.POST("/result/add", server.AddResult)
		system.GET("/result/list", server.GetResultList)
		system.GET("/result/:id", server.GetResultById)
		system.DELETE("/result/:id", server.DropResult)
	}
	//社区
	{
		system.POST("/community/add", server.AddCommunity)
		system.GET("/community/list", server.GetCommunityList)
		system.DELETE("/community/:id", server.DropCommunity)
	}
	//物品
	{
		system.POST("/goods/add", server.AddGoods)
		system.GET("/goods/list", server.GetGoodsList)
		system.PUT("/goods/update", server.ChangeGoods)
		system.DELETE("/goods/:id", server.DropGoods)
		system.GET("/goods/:id", server.GetGoodById)
		system.GET("/goods/put", server.PutGood)
		system.GET("/goods/out", server.OutGood)
	}
	//推送
	{
		system.POST("/push/add", server.AddPush)
		system.PUT("/push/change", server.UpdatePush)
		system.GET("/push/list", server.GetPushList)
		system.GET("/push/:id", server.GetPushById)
		system.DELETE("/push/:id", server.DropPush)
	}
	//居民
	{
		system.POST("/people/add", server.AddPeople)
		system.GET("/people/list", server.GetPeopleList)
		system.DELETE("/people/:id", server.DropPeople)
		system.PUT("/people/update", server.UpdatePeople)
	}
	//反馈
	{
		system.POST("/feedback/add", server.AddFeedback)
		system.PUT("/feedback/:id", server.ChangeFeedback)
		system.GET("/feedback/list", server.GetFeedbackList)
		system.DELETE("/feedback/:id", server.DropFeedback)
	}
}
