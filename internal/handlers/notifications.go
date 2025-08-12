package handlers

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/nats-io/nats.go"
	"k8s.io/klog/v2"
)

type Topic interface {
	String() string
}

var _ Topic = UserTopic("")
var _ Topic = GroupTopic("")

type UserTopic string
type GroupTopic string

const (
	TopicLogin           UserTopic  = "Login"
	TopicLogout          UserTopic  = "Logout"
	TopicOnFirstFactor   UserTopic  = "OnFirstFactor"
	TopicLoginFailed     UserTopic  = "LoginFailed"
	TopicSignCancel      UserTopic  = "SignCancel"
	TopicGroupCreated    GroupTopic = "Create"
	TopicGroupDeleted    GroupTopic = "Delete"
	TopicGroupModify     GroupTopic = "Modify"
	TopicGroupAddUser    GroupTopic = "MemberAdd"
	TopicGroupRemoveUser GroupTopic = "MemberDeleted"
)

func (t UserTopic) String() string {
	return string(t)
}

func (t UserTopic) send(ctx *middlewares.AutheliaCtx, username string, additional ...map[string]interface{}) {
	sendWithTopic(ctx, username, t, additional...)
}

func sendNotification(subject string, data interface{}) error {
	natsHost := os.Getenv("NATS_HOST")
	natsPort := os.Getenv("NATS_PORT")
	natsUsername := os.Getenv("NATS_USERNAME")
	natsPassword := os.Getenv("NATS_PASSWORD")

	nc, err := nats.Connect(fmt.Sprintf("nats://%s:%s", natsHost, natsPort), nats.UserInfo(natsUsername, natsPassword))
	if err != nil {
		return fmt.Errorf("error connecting to NATS: %v", err)
	}
	klog.Infoln("Connected to NATS", natsHost, natsPort, natsUsername)

	msg, err := json.Marshal(data)
	if err != nil {
		klog.Error("encode msg error, ", err)
		return err
	}
	klog.Infof("message... %s", string(msg))

	err = nc.Publish(subject, msg)
	if err != nil {
		klog.Error("publish message to nats error, ", err)
		return err
	}

	klog.Infof("published to subject: %s success ", subject)
	return nil
}

func sendWithTopic(ctx *middlewares.AutheliaCtx, username string, topic UserTopic, additionals ...map[string]interface{}) {
	payload := map[string]interface{}{
		"user": username,
		"ip":   ctx.RemoteIP().String(),
	}

	for _, additional := range additionals {
		for k, v := range additional {
			payload[k] = v
		}
	}

	data := map[string]interface{}{
		"payload": payload,
		"topic":   topic,
	}
	natsSubject := os.Getenv("NATS_SUBJECT_FOR_USERS")

	if err := sendNotification(natsSubject, data); err != nil {
		ctx.Logger.Errorf("send notification to user %s error, %+v", username, err)
	}
}

func (t GroupTopic) String() string {
	return string(t)
}

func (t GroupTopic) send(ctx *middlewares.AutheliaCtx, groupName, operator string, additionals ...map[string]interface{}) {
	sendGroupTopic(ctx, groupName, operator, t, additionals...)
}

func sendGroupTopic(ctx *middlewares.AutheliaCtx, groupName, operator string, topic GroupTopic, additionals ...map[string]interface{}) {
	payload := map[string]interface{}{
		"groupName": groupName,
		"operator":  operator,
		"timestamp": time.Now(),
	}
	for _, additional := range additionals {
		for k, v := range additional {
			payload[k] = v
		}
	}

	data := map[string]interface{}{
		"payload": payload,
		"topic":   topic,
	}
	natsSubject := os.Getenv("NATS_SUBJECT_FOR_GROUPS")
	if err := sendNotification(natsSubject, data); err != nil {
		ctx.Logger.Errorf("send group notification error %+v", err)
	}
}
